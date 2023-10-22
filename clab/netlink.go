// Copyright 2020 Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package clab

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/srl-labs/containerlab/types"
	"github.com/srl-labs/containerlab/utils"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type vEthEndpoint struct {
	Link      netlink.Link
	LinkName  string
	NSName    string // netns name
	NSPath    string // netns path
	Bridge    string // bridge name a veth is destined to be connected to
	OvsBridge string // ovs-bridge name a veth is destined to be connected to
}

// CreateVirtualWiring creates the virtual topology between the containers.
func (c *CLab) CreateVirtualWiring(ctx context.Context, l *types.Link) (err error) {
	log.Infof("Creating virtual wire: %s:%s <--> %s:%s", l.A.Node.ShortName, l.A.EndpointName, l.B.Node.ShortName, l.B.EndpointName)

	// connect containers (or container and a bridge) using veth pair
	// based on the link configuration contained within *Link struct
	// veth side A
	vA := vEthEndpoint{
		LinkName: l.A.EndpointName,
		NSName:   l.A.Node.LongName,
		NSPath:   fmt.Sprintf("/run/netns/%s", c.Config.Name),
	}
	// veth side B
	vB := vEthEndpoint{
		LinkName: l.B.EndpointName,
		NSName:   l.B.Node.LongName,
		NSPath:   fmt.Sprintf("/run/netns/%s", c.Config.Name),
	}

	log.Infof("Namespace for LinkA is %s and LinkB is %s", vA.NSPath, vB.NSPath)
	// get random names for veth sides as they will be created in root netns first
	ARndmName := fmt.Sprintf("clab-%s", genIfName())
	BRndmName := fmt.Sprintf("clab-%s", genIfName())

	// set bridge name for endpoint that should be connect to linux bridge
	switch {
	case l.A.Node.Kind == "bridge":

		// mgmt-net is a reserved node name that means
		// connect this endpoint to docker management bridged network
		if l.A.Node.ShortName != "mgmt-net" {
			vA.Bridge = l.A.Node.ShortName
		} else {
			vA.Bridge = c.Config.Mgmt.Bridge
		}
		// veth endpoint destined to connect to the bridge in the host netns
		// will not have a random name
		ARndmName = l.A.EndpointName
	case l.B.Node.Kind == "bridge":
		if l.B.Node.ShortName != "mgmt-net" {
			vB.Bridge = l.B.Node.ShortName
		} else {
			vB.Bridge = c.Config.Mgmt.Bridge
		}
		BRndmName = l.B.EndpointName
	case l.A.Node.Kind == "ovs-bridge":
		vA.OvsBridge = l.A.Node.ShortName
		ARndmName = l.A.EndpointName
	case l.B.Node.Kind == "ovs-bridge":
		vB.OvsBridge = l.B.Node.ShortName
		BRndmName = l.B.EndpointName
	// for host connections random names shouldn't be used
	case l.A.Node.Kind == "host":
		ARndmName = l.A.EndpointName
	case l.B.Node.Kind == "host":
		BRndmName = l.B.EndpointName
	}

	// Generate MAC addresses
	aMAC, err := net.ParseMAC(l.A.MAC)
	if err != nil {
		return err
	}
	bMAC, err := net.ParseMAC(l.B.MAC)
	if err != nil {
		return err
	}

	// Obtain the netns from A side
	vA.Link, vB.Link, err = createVethIface(ARndmName, BRndmName, l.MTU, vA.NSPath, aMAC, bMAC)
	if err != nil {
		return err
	}

	// once veth pair is created, disable tx offload for veth pair
	if err := utils.EthtoolTXOff(ARndmName); err != nil {
		return err
	}
	log.Debug("After EthtoolTXOff on A")
	if err := utils.EthtoolTXOff(BRndmName); err != nil {
		return err
	}
	log.Debug("After EthtoolTXOff on B")

	if err = vA.setVethLink(); err != nil {
		_ = netlink.LinkDel(vA.Link)
		return err
	}
	log.Debug("After setVethLink on A")
	if err = vB.setVethLink(); err != nil {
		_ = netlink.LinkDel(vB.Link)
	}
	log.Debug("After setVethLink on B")
	return err
}

// RemoveHostOrBridgeVeth tries to remove veths connected to the host network namespace or a linux bridge
// and does nothing in case they are not found.
func (c *CLab) RemoveHostOrBridgeVeth(l *types.Link) (err error) {
	switch {
	case l.A.Node.Kind == "host" || l.A.Node.Kind == "bridge":
		link, err := netlink.LinkByName(l.A.EndpointName)
		if err != nil {
			log.Debugf("Link %q is already gone: %v", l.A.EndpointName, err)
			break
		}

		log.Debugf("Cleaning up virtual wire: %s:%s <--> %s:%s", l.A.Node.ShortName,
			l.A.EndpointName, l.B.Node.ShortName, l.B.EndpointName)

		err = netlink.LinkDel(link)
		if err != nil {
			log.Debugf("Link %q is already gone: %v", l.A.EndpointName, err)
		}
	case l.B.Node.Kind == "host" || l.B.Node.Kind == "bridge":
		link, err := netlink.LinkByName(l.B.EndpointName)
		if err != nil {
			log.Debugf("Link %q is already gone: %v", l.B.EndpointName, err)
			break
		}

		log.Debugf("Cleaning up virtual wire: %s:%s <--> %s:%s", l.A.Node.ShortName,
			l.A.EndpointName, l.B.Node.ShortName, l.B.EndpointName)

		err = netlink.LinkDel(link)
		if err != nil {
			log.Debugf("Link %q is already gone: %v", l.B.EndpointName, err)
		}
	}
	return nil
}

// createVethIface takes two veth endpoint structs and create a veth pair and return
// veth interface links.
func createVethIface(ifName, peerName string, mtu int, nspath string, aMAC, bMAC net.HardwareAddr) (linkA, linkB netlink.Link, err error) {
	log.Info("Inside 'createVethIface")
	log.Debugf("nspath = %s", nspath)

	namespace, err := netns.GetFromPath(nspath)
	if err != nil {
		return nil, nil, err
	}
	linkA = &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         ifName,
			HardwareAddr: aMAC,
			Flags:        net.FlagUp,
			MTU:          mtu,
			Namespace:    namespace,
		},
		PeerName:         peerName,
		PeerHardwareAddr: bMAC,
		PeerNamespace:    namespace,
	}

	if err := netlink.LinkAdd(linkA); err != nil {
		return nil, nil, err
	}

	if linkB, err = netlink.LinkByName(peerName); err != nil {
		err = fmt.Errorf("failed to lookup %q: %v", peerName, err)
	}

	// Move them to the lab namespace

	log.Infof("End of createVethIface")
	return
}

// setVethLink sets the veth link endpoints to the relevant namespaces and/or connects one end to the bridge.
func (veth *vEthEndpoint) setVethLink() error {
	// if veth is destined to connect to a linux bridge in the host netns
	if veth.Bridge != "" {
		return veth.toBridge()
	}
	if veth.OvsBridge != "" {
		return veth.toOvsBridge()
	}
	// host endpoints have a special NSPath value
	// the host portion of veth doesn't need to be additionally processed
	if veth.NSPath == hostNSPath {
		if err := netlink.LinkSetUp(veth.Link); err != nil {
			return fmt.Errorf("failed to set %q up: %v",
				veth.LinkName, err)
		}
		return nil
	}
	// otherwise it needs to be put into a netns
	return veth.toNS()
}

// toNS puts a veth endpoint to a given netns and renames its random name to a desired name.
func (veth *vEthEndpoint) toNS() error {
	var vethNS ns.NetNS
	var err error
	if vethNS, err = ns.GetNS(veth.NSPath); err != nil {
		return err
	}
	// move veth endpoint to namespace
	if err = netlink.LinkSetNsFd(veth.Link, int(vethNS.Fd())); err != nil {
		return err
	}
	err = vethNS.Do(func(_ ns.NetNS) error {
		if err = netlink.LinkSetName(veth.Link, veth.LinkName); err != nil {
			return fmt.Errorf(
				"failed to rename link: %v", err)
		}

		if err = netlink.LinkSetUp(veth.Link); err != nil {
			return fmt.Errorf("failed to set %q up: %v",
				veth.LinkName, err)
		}
		return nil
	})
	return err
}

func (veth *vEthEndpoint) toBridge() error {
	var vethNS ns.NetNS
	var err error
	// bridge is in the host netns, thus we need to get current netns
	if vethNS, err = ns.GetCurrentNS(); err != nil {
		return err
	}
	err = vethNS.Do(func(_ ns.NetNS) error {
		br, err := utils.BridgeByName(veth.Bridge)
		if err != nil {
			return err
		}

		// connect host veth end to the bridge
		if err := netlink.LinkSetMaster(veth.Link, br); err != nil {
			return fmt.Errorf("failed to connect %q to bridge %v: %v", veth.LinkName, veth.Bridge, err)
		}

		if err = netlink.LinkSetUp(veth.Link); err != nil {
			return fmt.Errorf("failed to set %q up: %v", veth.LinkName, err)
		}
		return nil
	})
	return err
}

func genIfName() string {
	s, _ := uuid.New().MarshalText() // .MarshalText() always return a nil error
	return string(s[:8])
}

// GetLinksByNamePrefix returns a list of links whose name matches a prefix.
func GetLinksByNamePrefix(prefix string) ([]netlink.Link, error) {
	// filtered list of interfaces
	if prefix == "" {
		return nil, fmt.Errorf("prefix is not specified")
	}
	var fls []netlink.Link

	ls, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, l := range ls {
		if strings.HasPrefix(l.Attrs().Name, prefix) {
			fls = append(fls, l)
		}
	}
	if len(fls) == 0 {
		return nil, fmt.Errorf("no links found by specified prefix %s", prefix)
	}
	return fls, nil
}
