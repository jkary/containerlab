package lxc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	sysruntime "runtime"
	"strings"
	"time"

	lxd "github.com/canonical/lxd/client"
	"github.com/canonical/lxd/shared/api"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/srl-labs/containerlab/clab/exec"
	"github.com/srl-labs/containerlab/runtime"
	"github.com/srl-labs/containerlab/types"
	"github.com/srl-labs/containerlab/utils"
	"github.com/vishvananda/netns"
	// "golang.org/x/tools/go/analysis/passes/nilfunc"
	// "golang.org/x/tools/go/analysis/passes/nilfunc"
)

const (
	lxcNamespace = "lxdbr0"
	// cniCache            = "/opt/cni/cache".
	RuntimeName    = "lxc"
	defaultTimeout = 30 * time.Second
)

type LxdRuntime struct {
	config      runtime.RuntimeConfig
	client      lxd.InstanceServer
	mgmt        *types.MgmtNet
	labName     string
	netnsHandle netns.NsHandle
}

func init() {
	runtime.Register(RuntimeName, func() runtime.ContainerRuntime {

		// var mgmtNet types.MgmtNet

		client, err := lxd.ConnectLXDUnix("/run/lxd.socket", nil)
		if err != nil {
			log.Errorf("Unable to connect to lxd socket. (%s)", err)
			return nil
		}

		// networks, err := client.GetNetworks()
		// if err != nil {
		// 	log.Errorf("Unable to collect networks from LXD (%s)", err)

		// 	return nil
		// }

		// for _, network := range networks {
		// 	// Scan for default LXC mgmt network
		// 	if network.Name == "lxdbr0" {
		// 		mgmtNet.Network = network.Name
		// 		mgmtNet.Bridge = network.Name
		// 		mgmtNet.IPv4Subnet = network.Config["ipv4.address"]
		// 		mgmtNet.IPv6Subnet = network.Config["ipv6.address"]
		// 		break
		// 	}
		// }

		return &LxdRuntime{
			client: client,
			mgmt:   &types.MgmtNet{},
		}
	})
}

func (c *LxdRuntime) Init(opts ...runtime.RuntimeOption) error {

	log.Debug("Runtime: lxc")
	binaries := []string{"ip", "bridge"}
	for _, binary := range binaries {
		binary = filepath.Join("/usr/sbin", binary)
		if _, err := os.Stat(binary); err != nil {
			return errors.WithMessagef(err, "LXC binaries not found. [ %s ] are required.", strings.Join(binaries, ","))
		}
	}

	UseProject(nil, c)
	for _, o := range opts {
		o(c)
	}
	return nil
}

func (c *LxdRuntime) Mgmt() *types.MgmtNet { return c.mgmt }

func (c *LxdRuntime) WithConfig(cfg *runtime.RuntimeConfig) {
	c.config.Timeout = cfg.Timeout
	c.config.Debug = cfg.Debug
	c.config.GracefulShutdown = cfg.GracefulShutdown
	if c.config.Timeout <= 0 {
		c.config.Timeout = defaultTimeout
	}
}

func (c *LxdRuntime) WithMgmtNet(n *types.MgmtNet) {
	if n.Network != "clab" {
		c.mgmt = n
	} else {
		c.mgmt = &types.MgmtNet{
			Network: c.labName + "-mgmt",
			MTU:     "1500",
			Bridge:  c.labName + "-mgmt",
		}
	}
}

func (c *LxdRuntime) WithKeepMgmtNet() {
	c.config.KeepMgmtNet = true
}

func (c *LxdRuntime) WithLabName(name string) {
	log.Infof("Lab name is %s", name)
	c.labName = name
}

func (*LxdRuntime) GetName() string                 { return RuntimeName }
func (c *LxdRuntime) Config() runtime.RuntimeConfig { return c.config }

// Discover or create the project in question.
func UseProject(ctx context.Context, c *LxdRuntime) error {

	names, err := c.client.GetProjectNames()
	if err != nil {
		return fmt.Errorf("unable to list projects (%s)", err)
	}

	for _, name := range names {
		log.Debugf("Project %s found.", name)
		if name == c.labName {
			c.client = c.client.UseProject(name)
			return nil
		}
	}

	// If project is not found then create it.
	log.Infof("Creating project %s", c.labName)
	if err = c.client.CreateProject(api.ProjectsPost{
		Name: c.labName,
		ProjectPut: api.ProjectPut{
			// Contain networking to the network namespace.  TODO:  Need to create netns
			Config: map[string]string{"features.networks": "false", "features.images": "false"},
		}}); err != nil {
		return err
	}

	// Create a net namespace if not defined.
	netnsPath := fmt.Sprintf("/run/netns/%s", c.labName)
	log.Debugf("netnsPath is %s", netnsPath)
	if _, err := os.Stat(netnsPath); os.IsNotExist(err) {
		// Create netns
		handle, err := netns.NewNamed(c.labName)
		if err != nil {
			return err
		}
		c.netnsHandle = handle
		c.client = c.client.UseProject(c.labName)
	}
	return nil
}

func (c *LxdRuntime) CreateNet(ctx context.Context) error {
	_, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	if c.netnsHandle == -1 {
		return errors.Errorf("Runtime not setup properly. netnsHandle = %s", c.netnsHandle)
	}

	mgmt, _, err := c.client.GetNetwork(c.mgmt.Network)
	log.Debugf("Getting network %s. mgmt is %s, err is %s", c.mgmt.Network, mgmt.Name, err)
	if err != nil && err.Error() == "Network not found" {
		log.Debug("Creating mgmt network")
		network := api.NetworksPost{
			NetworkPut: api.NetworkPut{
				Description: fmt.Sprintf("Management network for %s", c.mgmt.Network),
				// TODO: Add subnet support
				Config: map[string]string{"ipv4.address": "172.16.0.10/24", "ipv4.nat": "true", "ipv6.address": "none"},
			},
			Type: "bridge",
			Name: c.mgmt.Network,
		}
		err = c.client.CreateNetwork(network)
		if err != nil {
			return fmt.Errorf("fooo unable to create management network. (%s)", err)
		}
		mgmt, _, err = c.client.GetNetwork(c.mgmt.Network)
		if err != nil {
			return err
		}
	}
	log.Infof("Management Network is %s inside project %s", c.mgmt.Network, mgmt.Name)
	if mgmt != nil {
		log.Infof("Mgmt is %+v", mgmt)
	}
	log.Debug("End of createNet")
	return nil
}

func (c *LxdRuntime) DeleteNet(ctx context.Context) error {
	log.Debugf("Delete() - deleting network %s", c.mgmt.Network)
	_, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	var err error
	bridgename := c.mgmt.Bridge
	brInUse := true
	for i := 0; i < 10; i++ {
		brInUse, err = utils.CheckBrInUse(bridgename)
		if err != nil {
			return err
		}
		time.Sleep(time.Millisecond * 100)
		if !brInUse {
			// Stop early if bridge no longer in use
			// Need to wait some time, since the earlier veth deletion
			// triggert from the container deletion is async and needs
			// to finish. W'll have a race condition otherwise.
			break
		}
	}
	if c.config.KeepMgmtNet || brInUse {
		log.Infof("Skipping deletion of bridge '%s'", bridgename)
		return nil
	}

	return utils.DeleteLinkByName(bridgename)
}

func (c *LxdRuntime) PullImage(ctx context.Context, imageName string, pullPolicy types.PullPolicyValue) error {
	images, err := c.client.GetImages()
	if err != nil {
		return err
	}

	for _, image := range images {
		for _, alias := range image.Aliases {
			if alias.Name == imageName {
				return nil
			}
			if image.Fingerprint == imageName {
				return nil
			}
		}
	}

	return fmt.Errorf("image %s was not found", imageName)
}

func (c *LxdRuntime) CreateContainer(ctx context.Context, nodeCfg *types.NodeConfig) (string, error) {
	_, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	var err error

	// Lock the OS Thread so we don't accidentally switch namespaces
	sysruntime.LockOSThread()
	// Create the lab netns and runtime path.
	// Unlike containerd, I don't think we need a separate NS for each container.
	if c.netnsHandle, err = netns.GetFromName(c.labName); c.netnsHandle == -1 {
		if err != nil {
			log.Debugf("Named netns not found. (%s)", err)
		}

		// log.Debugf("Creating netns %s", c.labName)
		// c.netnsHandle, err = netns.NewNamed(c.labName)
		// if err != nil {
		// 	return "", err
		// }
	}
	sysruntime.UnlockOSThread()

	if err := UseProject(ctx, c); err != nil {
		return "", err
	}

	if nodeCfg.Kind == "vr-nxos" {

		req, err := createLxdRequest(c, nodeCfg)
		if err != nil {
			return "", err
		}

		// Get LXD to create the instance (background operation)
		op, err := c.client.CreateInstance(*req)
		if err != nil {
			return "", err
		}

		if err = op.Wait(); err != nil {
			return "", err
		}

	} else {
		return "", fmt.Errorf("instances can only be run on nxos")
	}
	return nodeCfg.LongName, nil
}

func createLxdNetRequest(c *LxdRuntime) error {

	newNetwork := api.NetworksPost{
		Name: c.labName + "-mgmt",
		NetworkPut: api.NetworkPut{
			Config:      map[string]string{"ipv4.address": "172.16.0.0/24"},
			Description: "Mgmt network",
		},
	}

	if err := c.client.CreateNetwork(newNetwork); err != nil {
		return err

	}

	listNetworks(c)
	return nil

}

func listNetworks(c *LxdRuntime) error {
	networks, err := c.client.GetNetworks()
	if err != nil {
		return err
	}

	for _, net := range networks {
		log.Debugf("Network: %s", net.Name)
	}

	return nil
}

func createLxdRequest(c *LxdRuntime, nodeCfg *types.NodeConfig) (*api.InstancesPost, error) {
	// Note we don't need profile because we create the custom device list here.
	instPut := api.InstancePut{
		Devices: map[string]map[string]string{
			"eth0": {
				"network": c.labName + "-mgmt",
				"type":    "nic",
			},
			"root": {
				"path": "/",
				"pool": "lxc_zfs_01",
				"type": "disk",
			},
		},
		Ephemeral: false,
	}

	// Merge in endpoints
	// endpoints := createEndpointNetworks(c.labName, nodeCfg.Endpoints)
	// for key, value := range endpoints {
	// 	instPut.Devices[key] = value
	// }

	req := api.InstancesPost{
		Name: nodeCfg.LongName,
		Source: api.InstanceSource{
			Project: c.labName,
			Type:    "image",
			Alias:   "nxos9300v",
		},
		Type:        "container",
		InstancePut: instPut,
	}

	return &req, nil
}

func createEndpointNetworks(prefix string, endpoints []types.Endpoint) map[string]map[string]string {
	if len(endpoints) == 0 || endpoints == nil {
		return nil
	}

	networks := make(map[string]map[string]string)
	for index, endp := range endpoints {
		intf := fmt.Sprintf("eth%d", index+1)
		networks[intf] = map[string]string{
			"network": prefix + endp.EndpointName,
			"type":    "nic",
		}
	}

	return networks
}

func (c *LxdRuntime) StartContainer(ctx context.Context, _ string, node *types.NodeConfig) (interface{}, error) {
	// Really only used by ignite to get an interface for receiving events back from the
	// container.
	// I use it here to keep the semantics.
	_, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// Get LXD to start the instance (background operation)
	reqState := api.InstanceStatePut{
		Action:  "start",
		Timeout: -1,
	}

	op, err := c.client.UpdateInstanceState(node.LongName, reqState, "")
	if err != nil {
		return nil, err
	}

	// Wait for the operation to complete
	if err = op.Wait(); err != nil {
		return "", err
	}
	return nil, nil
}

func (c *LxdRuntime) PauseContainer(ctx context.Context, cID string) error {
	_, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// Get LXD to start the instance (background operation)
	reqState := api.InstanceStatePut{
		Action:  "freeze",
		Timeout: -1,
	}

	op, err := c.client.UpdateInstanceState(cID, reqState, "")
	if err != nil {
		return err
	}

	// Wait for the operation to complete
	if err = op.Wait(); err != nil {
		return err
	}
	return nil
}

func (c *LxdRuntime) UnpauseContainer(ctx context.Context, cID string) error {
	_, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// Get LXD to start the instance (background operation)
	reqState := api.InstanceStatePut{
		Action:  "unfreeze",
		Timeout: -1,
	}

	op, err := c.client.UpdateInstanceState(cID, reqState, "")
	if err != nil {
		return err
	}

	// Wait for the operation to complete
	if err = op.Wait(); err != nil {
		return err
	}
	return nil
}

func (c *LxdRuntime) StopContainer(ctx context.Context, containername string) error {
	_, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// Get LXD to start the instance (background operation)
	reqState := api.InstanceStatePut{
		Action:  "stop",
		Timeout: -1,
	}

	op, err := c.client.UpdateInstanceState(containername, reqState, "")
	if err != nil {
		return err
	}

	// Wait for the operation to complete
	if err = op.Wait(); err != nil {
		return err
	}
	return nil
}

func (c *LxdRuntime) ListContainers(ctx context.Context, filter []*types.GenericFilter) ([]runtime.GenericContainer, error) {
	log.Debug("listing containers")
	// TODO: Use filters from lxc

	var containers []runtime.GenericContainer
	if err := UseProject(ctx, c); err != nil {
		return nil, fmt.Errorf("project error: %s", err)
	}

	instances, err := c.client.GetInstances(api.InstanceTypeAny)
	if err != nil {
		return nil, fmt.Errorf("unable to get instances. %s", err)
	}
	for _, instance := range instances {
		if instance.Project != c.labName {
			continue
		}
		containers = append(containers, runtime.GenericContainer{
			Names:   []string{instance.Name},
			ID:      instance.Name,
			ShortID: instance.Name,
			State:   instance.Status,
			Status:  instance.Status,
		})
	}
	return containers, nil
}

func (c *LxdRuntime) GetNSPath(ctx context.Context, containername string) (string, error) {
	// Links all live within the same namespace
	namespace := fmt.Sprintf("/run/lxc/%s", c.labName)
	if _, err := os.Stat(namespace); os.IsNotExist(err) {
		return "", fmt.Errorf("namespace path error (%s)", err)
	}
	return namespace, nil
}

func (c *LxdRuntime) Exec(ctx context.Context, containername string, exec *exec.ExecCmd) (*exec.ExecResult, error) {
	return nil, fmt.Errorf("Exec - Non implemented.")
}

func (c *LxdRuntime) ExecNotWait(ctx context.Context, containername string, exec *exec.ExecCmd) error {
	return fmt.Errorf("Exec - Non implemented.")
}

func (c *LxdRuntime) DeleteContainer(ctx context.Context, containerID string) error {
	log.Debugf("deleting container %s", containerID)
	op, err := c.client.DeleteInstance(containerID)
	if err != nil {
		return fmt.Errorf("Instance %s not able to be destroyed. (%s)", containerID, err)
	}

	if err = op.Wait(); err != nil {
		return err
	}

	log.Debugf("successfully deleted container %s", containerID)

	return nil
}

// GetHostsPath returns fs path to a file which is mounted as /etc/hosts into a given container
// TODO: do we need it here? currently no-op.
func (c *LxdRuntime) GetHostsPath(context.Context, string) (string, error) {
	return "", fmt.Errorf("Not implemented")
}

// GetContainerStatus retrieves the ContainerStatus of the named container.
func (c *LxdRuntime) GetContainerStatus(ctx context.Context, cID string) runtime.ContainerStatus {
	log.Debugf("Get container %s status", cID)
	inst, _, err := c.client.GetInstance(cID)
	if err != nil {
		return runtime.NotFound
	}

	return runtime.ContainerStatus(inst.Status)
}
