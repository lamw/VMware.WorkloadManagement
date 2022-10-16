Function New-WorkloadManagement4 {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          09/18/2022
        Organization:  VMware
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================

        .SYNOPSIS
            Enable Workload Management on vSphere 8 Cluster w/vSphere Zones using vSphere networking with HAProxy
        .DESCRIPTION
            Enable Workload Management on vSphere 8 Cluster w/vSphere Zones using vSphere networking with HAProxy
        .PARAMETER VsphereZoneName
            Name of the vSphere Zone (default: vz-01)
        .PARAMETER SupervisorClusterName
            Name of the Supervisor Cluster (default: svc-01)
        .PARAMETER ClusterName
            Name of vSphere Cluster to enable Workload Management
        .PARAMETER TanzuvCenterServer
            Hostname/IP of the new Tanzu vCenter Server that was deployed
        .PARAMETER TanzuvCenterServerUsername
            Username to connect to new Tanzu vCenter Server
        .PARAMETER TanzuvCenterServerPassword
            Password to connect to new Tanzu vCenter Server
        .PARAMETER TanzuContentLibrary
            Name of the Tanzu Kubernetes Grid subscribed Content Library
        .PARAMETER ControlPlaneSize
            Size of Control Plane VMs (TINY, SMALL, MEDIUM, LARGE)
        .PARAMETER HAProxyVMName
            The display name of the HAProxy VM
        .PARAMETER HAProxyRootPassword
            Root password for HAProxy VM
        .PARAMETER HAProxyUsername
            HAProxy Control Plane Username (default: wcp)
        .PARAMETER HAProxyPassword
            HAProxy Control Plane Password
        .PARAMETER HAProxyIPAddress
            HAProxy VM Control Plane IP Address
        .PARAMETER HAProxyPort
            HAProxy Control Plane port (default: 5556)
        .PARAMETER HAProxyVMvCenterServer
            Hostname/IP of the vCenter Server managing HAProxy VM to automatically retrieve CA certificate
        .PARAMETER HAProxyVMvCenterUsername
            Username to connect to vCenter Server managing HAProxy VM to automatically retrieve CA certificate
        .PARAMETER HAProxyVMvCenterPassword
            Password to connect to vCenter Server managing HAProxy VM to automatically retrieve CA certificate
        .PARAMETER MgmtNetwork
            Supervisor Management Network for Control Plane VMs
        .PARAMETER MgmtNetworkStartIP
            Starting IP Address for Control Plane VMs (5 consecutive free addresses)
        .PARAMETER MgmtNetworkSubnet
            Netmask for Management Network
        .PARAMETER MgmtNetworkGateway
            Gateway for Management Network
        .PARAMETER MgmtNetworkDNS
            DNS Server(s) to use for Management Network
        .PARAMETER MgmtNetworkDNSDomain
            DNS Domain(s) to use for Management Network
        .PARAMETER MgmtNetworkNTP
            NTP Server(s) to use for Management Network
        .PARAMETER WorkloadNetworkLabel
            Workload Network label defined in vSphere with Tanzu (default: workload-1)
        .PARAMETER WorkloadNetwork
            Workload Network
        .PARAMETER WorkloadNetworkStartIP
            Starting IP Address for Workload VMs
        .PARAMETER WorkloadNetworkIPCount
            Number of IP Addresses to allocate from starting from WorkloadNetworkStartIP
        .PARAMETER WorkloadNetworkSubnet
            Subnet for Workload Network
        .PARAMETER WorkloadNetworkGateway
            Gateway for Workload Network
        .PARAMETER WorkloadNetworkDNS
            DNS Server(s) to use for Workloads
        .PARAMETER WorkloadNetworkDNSDomain
            DNS Domain(s) to use for Workloads
        .PARAMETER WorkloadNetworkNTP
            NTP Server(s) to use for Workloads
        .PARAMETER WorkloadNetworkServiceStartIP
            Starting IP Address for K8S Service (default: 10.96.0.0)
        .PARAMETER WorkloadNetworkServiceCount
            Number of IP Addrsses to allocate from WorkloadNetworkServiceStartIP (default: 256)
        .PARAMETER StoragePolicyName
            Name of VM Storage Policy to use for Control Plane VMs, Ephemeral Disks & Image Cache
        .PARAMETER LoadBalancerLabel
            Load Balancer label defined in vSphere with Tanzu (default: tanzu-haproxy-1)
        .PARAMETER LoadBalancerStartIP
            Starting IP Address for HAProxy Load Balancer
        .PARAMETER LoadBalancerIPCount
            Number of IP Addresses to allocate from starting from LoadBalancerStartIP
        .PARAMETER LoginBanner
            Login message to show during kubectl login
        .EXAMPLE
            $vSphereWithTanzuParams = @{
                VsphereZoneName = "vz-01"
                SupervisorClusterName = "svc-01"
                ClusterName = "Tanzu-Cluster";
                TanzuvCenterServer = "vcsa.tanzu.local";
                TanzuvCenterServerUsername = "administrator@vsphere.local";
                TanzuvCenterServerPassword = "VMware1!";
                TanzuContentLibrary = "TKG-Content-Library";
                ControlPlaneSize = "TINY";
                MgmtNetwork = "management";
                MgmtNetworkStartIP = "192.168.30.20";
                MgmtNetworkPrefix = "24";
                MgmtNetworkGateway = "192.168.30.1";
                MgmtNetworkDNS = @("192.168.30.69");
                MgmtNetworkDNSDomain = "tanzu.local";
                MgmtNetworkNTP = @("162.159.200.123");
                WorkloadNetwork = "workload";
                WorkloadNetworkStartIP = "10.20.0.10";
                WorkloadNetworkIPCount = 20;
                WorkloadNetworkPrefix = "24";
                WorkloadNetworkGateway = "10.20.0.1";
                WorkloadNetworkDNS = @("10.20.0.1");
                WorkloadNetworkDNSDomain = "tanzu.local";
                WorkloadNetworkNTP = @("162.159.200.123");
                WorkloadNetworkServiceStartIP = "10.96.0.0";
                WorkloadNetworkServiceStartCount = "256";
                StoragePolicyName = "Tanzu-Storage-Policy";
                HAProxyVMvCenterServer = "vcsa.tanzu.local";
                HAProxyVMvCenterUsername = "administrator@vsphere.local";
                HAProxyVMvCenterPassword = "VMware1!";
                HAProxyVMName = "haproxy.tanzu.local";
                HAProxyIPAddress = "192.168.30.68";
                HAProxyRootPassword = "VMware1!";
                HAProxyPassword = "VMware1!";
                LoadBalancerStartIP = "10.10.0.64";
                LoadBalancerIPCount = 64;
            }

            New-WorkloadManagement4 @vSphereWithTanzuParams
    #>
    Param (
        [Parameter(Mandatory=$True)][string]$VsphereZoneName="vz-01",
        [Parameter(Mandatory=$True)][string]$SupervisorClusterName="svc-01",
        [Parameter(Mandatory=$True)][string]$HAProxyVMName,
        [Parameter(Mandatory=$True)][string]$HAProxyRootPassword,
        [Parameter(Mandatory=$False)][string]$HAProxyUsername="wcp",
        [Parameter(Mandatory=$True)][string]$HAProxyPassword,
        [Parameter(Mandatory=$True)][string]$HAProxyVMvCenterServer,
        [Parameter(Mandatory=$True)][string]$HAProxyVMvCenterUsername,
        [Parameter(Mandatory=$True)][string]$HAProxyVMvCenterPassword,
        [Parameter(Mandatory=$True)][string]$TanzuvCenterServer,
        [Parameter(Mandatory=$True)][string]$TanzuvCenterServerUsername,
        [Parameter(Mandatory=$True)][string]$TanzuvCenterServerPassword,
        [Parameter(Mandatory=$True)][string]$ClusterName,
        [Parameter(Mandatory=$True)][string]$TanzuContentLibrary,
        [Parameter(Mandatory=$True)][ValidateSet("TINY","SMALL","MEDIUM","LARGE")][string]$ControlPlaneSize,
        [Parameter(Mandatory=$False)]$MgmtNetwork="DVPG-Supervisor-Management-Network",
        [Parameter(Mandatory=$True)][string]$MgmtNetworkStartIP,
        [Parameter(Mandatory=$True)][string]$MgmtNetworkPrefix,
        [Parameter(Mandatory=$True)][string]$MgmtNetworkGateway,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkDNS,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkDNSDomain,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkNTP,
        [Parameter(Mandatory=$False)][string]$WorkloadNetworkLabel="workload-1",
        [Parameter(Mandatory=$False)][string]$WorkloadNetwork="DVPG-Workload-Network",
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkStartIP,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkIPCount,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkPrefix,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkGateway,
        [Parameter(Mandatory=$True)][string[]]$WorkloadNetworkDNS,
        [Parameter(Mandatory=$True)][string[]]$WorkloadNetworkDNSDomain,
        [Parameter(Mandatory=$True)][string[]]$WorkloadNetworkNTP,
        [Parameter(Mandatory=$False)][string]$WorkloadNetworkServiceStartIP="10.96.0.0",
        [Parameter(Mandatory=$False)][string]$WorkloadNetworkServiceStartCount="256",
        [Parameter(Mandatory=$False)][string]$LoadBalancerLabel="tanzu-haproxy-1",
        [Parameter(Mandatory=$True)][string]$HAProxyIPAddress,
        [Parameter(Mandatory=$False)][string]$HAProxyPort=5556,
        [Parameter(Mandatory=$True)][string]$LoadBalancerStartIP,
        [Parameter(Mandatory=$True)][string]$LoadBalancerIPCount,
        [Parameter(Mandatory=$True)]$StoragePolicyName,
        [Parameter(Mandatory=$False)]$LoginBanner,
        [Switch]$EnableDebug
    )

    Write-host -ForegroundColor Green "Connecting to Management vCenter Server $HAProxyVMvCenterServer to retrieve HAProxy CA Certificate ..."
    $viConnection = Connect-VIServer $HAProxyVMvCenterServer -User $HAProxyVMvCenterUsername -Password $HAProxyVMvCenterPassword -WarningAction SilentlyContinue
    $caCertCmd = "cat /etc/haproxy/ca.crt"
    $haProxyCert = (Invoke-VMScript -Server $viConnection -ScriptText $caCertCmd -vm (Get-VM -Server $viConnection -Name $HAProxyVMName) -GuestUser "root" -GuestPassword "$HAProxyRootPassword").ScriptOutput

    Write-host -ForegroundColor Green "Disconnecting from Management vCenter ..."
    Disconnect-VIServer $viConnection -Confirm:$false

    Write-host -ForegroundColor Green "Connecting to Tanzu vCenter Server to enable Workload Management ..."
    Connect-VIServer $TanzuvCenterServer -User $TanzuvCenterServerUsername -Password $TanzuvCenterServerPassword -WarningAction SilentlyContinue | Out-Null

    if( (Get-ContentLibrary -Name $TanzuContentLibrary).syncdate -eq $NULL ) {
        Write-host -ForegroundColor Green "TKG Content Library has not fully sync'ed, please try again later"
        Disconnect-VIServer * -Confirm:$false
        break
    } else {
        Connect-CisServer $TanzuvCenterServer -User $TanzuvCenterServerUsername -Password $TanzuvCenterServerPassword -WarningAction SilentlyContinue | Out-Null

        # Cluster Moref
        $clusterService = Get-CisService "com.vmware.vcenter.cluster"
        $clusterFilterSpec = $clusterService.help.list.filter.Create()
        $clusterFilterSpec.names = @("$ClusterName")
        $clusterMoRef = $clusterService.list($clusterFilterSpec).cluster.Value
        if ($clusterMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Cluster ${ClusterName}"
            break
        }

        # Management Network Moref
        $networkService = Get-CisService "com.vmware.vcenter.network"
        $networkFilterSpec = $networkService.help.list.filter.Create()
        $networkFilterSpec.names = @("$MgmtNetwork")
        $mgmtNetworkMoRef = $networkService.list($networkFilterSpec).network.Value
        if ($mgmtNetworkMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Management Network ${MgmtNetwork}"
            break
        }

        # Workload Network Moref
        $networkFilterSpec = $networkService.help.list.filter.Create()
        $networkFilterSpec.names = @("$WorkloadNetwork")
        $workloadNetworkMoRef = $networkService.list($networkFilterSpec).network.Value
        if ($workloadNetworkMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Workload Network ${WorkloadNetwork}"
            break
        }

        $storagePolicyService = Get-CisService "com.vmware.vcenter.storage.policies"
        $sps= $storagePolicyService.list()
        $pacificSP = ($sps | where {$_.name -eq $StoragePolicyName}).Policy.Value


        $supervisorService = Get-CisService "com.vmware.vcenter.namespace_management.supervisors"
        $spec = $supervisorService.Help.enable_on_compute_cluster.spec.Create()
        $spec.zone = $VsphereZoneName
        $spec.name = $SupervisorClusterName

        ## Control Plane Spec ##
        $cpNetworkSpec = $supervisorService.Help.enable_on_compute_cluster.spec.control_plane.network.Create()
        $cpNetworkSpec.network = $mgmtNetworkMoRef

        # Backing Network
        $backingSpec = $supervisorService.Help.enable_on_compute_cluster.spec.control_plane.network.backing.Create()
        $backingSpec.backing = "NETWORK"
        $backingSpec.network = $mgmtNetworkMoRef
        $cpNetworkSpec.backing = $backingSpec

        #IP Management
        $cpIpMgmtSpec = $supervisorService.Help.enable_on_compute_cluster.spec.control_plane.network.ip_management.Create()
        $cpIpMgmtSpec.dhcp_enabled = $False

        $cpRangeSpec = $supervisorService.Help.enable_on_compute_cluster.spec.control_plane.network.ip_management.ip_assignments.Element.ranges.Element.Create()
        $cpRangeSpec.address = $MgmtNetworkStartIP
        $cpRangeSpec.count = 5

        $cpIpMgmtSpec.gateway_address = "$MgmtNetworkGateway/$MgmtNetworkPrefix"
        $cpIpAssignmentSpec =  $supervisorService.Help.enable_on_compute_cluster.spec.control_plane.network.ip_management.ip_assignments.Element.Create()
        $cpIpAssignmentSpec.assignee = "NODE"
        $cpIpAssignmentSpec.ranges = @($cpRangeSpec)
        $cpIpMgmtSpec.ip_assignments = @($cpIpAssignmentSpec)
        $cpNetworkSpec.ip_management = $cpIpMgmtSpec

        # DNS/NTP Service
        $cpServiceSpec = $supervisorService.Help.enable_on_compute_cluster.spec.control_plane.network.services.Create()
        $cpDnsSpec = $supervisorService.Help.enable_on_compute_cluster.spec.control_plane.network.services.dns.Create()
        $cpDnsSpec.servers = @($MgmtNetworkDNS)
        $cpDnsSpec.search_domains = @($MgmtNetworkDNSDomain)
        $cpServiceSpec.dns = $cpDnsSpec
        $cpNtpSpec = $supervisorService.Help.enable_on_compute_cluster.spec.control_plane.network.services.ntp.Create()
        $cpNtpSpec.servers = @($MgmtNetworkNTP)
        $cpServiceSpec.ntp = $cpNtpSpec
        $cpNetworkSpec.services = $cpServiceSpec

        $spec.control_plane.network = $cpNetworkSpec
        $spec.control_plane.storage_policy = $pacificSP
        $spec.control_plane.size = $ControlPlaneSize

        $LoginBanner = "

        " + [char]::ConvertFromUtf32(0x1F973) + " vSphere with Tanzu using HAProxy & vSphere Zones enabled by William Lam's Script " + [char]::ConvertFromUtf32(0x1F973) + "

    "
        $spec.control_plane.login_banner = $LoginBanner

        ## Workloads Spec ##
        $wlSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.Create()

        # Network
        $wlNetworkSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.network.Create()
        $wlNetworkSpec.network_type = "VSPHERE"
        $wlNetworkSpec.network = $WorkloadNetworkLabel
        $vsphereNetworkSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.network.vsphere.Create()
        $vsphereNetworkSpec.dvpg = $workloadNetworkMoRef
        $wlNetworkSpec.vsphere = $vsphereNetworkSpec

        # DNS/NTP Services
        $wlServiceSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.network.services.Create()
        $wlDnsSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.network.services.dns.Create()
        $wlDnsSpec.servers = @($WorkloadNetworkDNS)
        $wlDnsSpec.search_domains = @($WorkloadNetworkDNSDomain)
        $wlServiceSpec.dns = $wlDnsSpec
        $wlNtpSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.network.services.ntp.Create()
        $wlNtpSpec.servers = $WorkloadNetworkNTP
        $wlServiceSpec.ntp = $wlNtpSpec
        $wlNetworkSpec.services = $wlServiceSpec

        # Workload & Workload Service IP Management
        $wlIpMgmtSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.network.ip_management.Create()
        $wlIpMgmtSpec.dhcp_enabled = $False
        $wlIpMgmtSpec.gateway_address = "$WorkloadNetworkGateway/$WorkloadNetworkPrefix"

        $wlIpAssignmentSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.network.ip_management.ip_assignments.Element.Create()
        $wlRangeSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.network.ip_management.ip_assignments.Element.ranges.Element.Create()
        $wlRangeSpec.address = $WorkloadNetworkStartIP
        $wlRangeSpec.count = $WorkloadNetworkIPCount
        $wlIpAssignmentSpec.ranges = @($wlRangeSpec)
        $wlIpAssignmentSpec.assignee = "NODE"

        $wlServiceIpAssignmentSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.network.ip_management.ip_assignments.Element.Create()
        $wlServiceRangeSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.network.ip_management.ip_assignments.Element.ranges.Element.Create()
        $wlServiceRangeSpec.address = $WorkloadNetworkServiceStartIP
        $wlServiceRangeSpec.count = $WorkloadNetworkServiceStartCount
        $wlServiceIpAssignmentSpec.ranges = @($wlServiceRangeSpec)
        $wlServiceIpAssignmentSpec.assignee = "SERVICE"

        $wlIpMgmtSpec.ip_assignments = @($wlIpAssignmentSpec, $wlServiceIpAssignmentSpec)
        $wlNetworkSpec.ip_management = $wlIpMgmtSpec

        $wlSpec.network = $wlNetworkSpec

        # Edge
        $wlEdgeSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.edge.Create()
        $wlEdgeSpec.id = $LoadBalancerLabel
        $wlEdgeSpec.provider = "HAPROXY"
        $lbRangeSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.edge.load_balancer_address_ranges.Element.Create()
        $lbRangeSpec.address = $LoadBalancerStartIP
        $lbRangeSpec.count = $LoadBalancerIPCount
        $wlEdgeSpec.load_balancer_address_ranges = @($lbRangeSpec)
        $haproxySpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.edge.haproxy.Create()
        $haproxyServerSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.edge.haproxy.servers.Element.Create()
        $haproxyServerSpec.host = $HAProxyIPAddress
        $haproxyServerSpec.port = $HAProxyPort
        $haproxySpec.servers = @($haproxyServerSpec)
        $haproxySpec.username = $HAProxyUsername
        $haproxySpec.password = [VMware.VimAutomation.Cis.Core.Types.V1.Secret]$HAProxyPassword
        $haproxySpec.certificate_authority_chain = $haProxyCert
        $wlEdgeSpec.haproxy = $haproxySpec
        $wlSpec.edge = $wlEdgeSpec

        # Images
        $wlImagesSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.images.Create()
        $wlImagesSpec.kubernetes_content_library = (Get-ContentLibrary -Name $TanzuContentLibrary)[0].id
        $wlSpec.images = $wlImagesSpec

        # Storage
        $wlStorageSpec = $supervisorService.Help.enable_on_compute_cluster.spec.workloads.storage.Create()
        $wlStorageSpec.ephemeral_storage_policy = $pacificSP
        $wlStorageSpec.image_storage_policy = $pacificSP
        $wlSpec.storage = $wlStorageSpec

        $spec.workloads = $wlSpec

        # Output JSON payload
        if($EnableDebug) {
            $spec | ConvertTo-Json -Depth 10
        }

        try {
            Write-host -ForegroundColor Green "Enabling Tanzu Workload Management on vSphere Cluster ${ClusterName} with vSphere Zones ..."
            $task = $supervisorService.enable_on_compute_cluster($clusterMoRef,$spec)
        } catch {
            Write-host -ForegroundColor red "Error in attempting to enable Tanzu Workload Management on vSphere Cluster ${ClusterName}"
            Write-host -ForegroundColor red "($_.Exception.Message)"
            Disconnect-VIServer * -Confirm:$false | Out-Null
            Disconnect-CisServer $global:DefaultCisServers -Confirm:$false | Out-Null
            break
        }
        Write-host -ForegroundColor Green "Please refer to the Tanzu Workload Management UI in vCenter Server to monitor the progress of this operation"

        Write-host -ForegroundColor Green "Disconnecting from Tanzu Management vCenter ..."
        Disconnect-VIServer * -Confirm:$false | Out-Null
        Disconnect-CisServer $global:DefaultCisServers -Confirm:$false | Out-Null
    }
}

Function New-WorkloadManagement3 {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          03/29/2021
        Organization:  VMware
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================

        .SYNOPSIS
            Enable Workload Management on vSphere 7.0 Update 2 Cluster using NSX Advanced Load Balancer (NSX ALB)
        .DESCRIPTION
            Enable Workload Management on vSphere 7.0 Update 2 Cluster using NSX Advanced Load Balancer (NSX ALB)
        .PARAMETER TanzuvCenterServer
            Hostname/IP of the new Tanzu vCenter Server that was deployed
        .PARAMETER TanzuvCenterServerUsername
            Username to connect to new Tanzu vCenter Server
        .PARAMETER TanzuvCenterServerPassword
            Password to connect to new Tanzu vCenter Server
        .PARAMETER ClusterName
            Name of vSphere Cluster to enable Workload Management
        .PARAMETER TanzuContentLibrary
            Name of the Tanzu Kubernetes Grid subscribed Content Library
        .PARAMETER ControlPlaneSize
            Size of Control Plane VMs (TINY, SMALL, MEDIUM, LARGE)
        .PARAMETER NSXALBIPAddress
            NSX ALB Management IP Address
        .PARAMETER NSXALBPort
            NSX ALB Management port (default: 443)
        .PARAMETER NSXALBUsername
            NSX ALB Username (default: admin)
        .PARAMETER NSXALBPassword
            NSX ALB Password
        .PARAMETER MgmtNetwork
            Supervisor Management Network for Control Plane VMs
        .PARAMETER MgmtNetworkStartIP
            Starting IP Address for Control Plane VMs (5 consecutive free addresses)
        .PARAMETER MgmtNetworkSubnet
            Netmask for Management Network
        .PARAMETER MgmtNetworkGateway
            Gateway for Management Network
        .PARAMETER MgmtNetworkDNS
            DNS Server(s) to use for Management Network
        .PARAMETER MgmtNetworkDNSDomain
            DNS Domain(s)
        .PARAMETER MgmtNetworkNTP
            NTP Server(s)
        .PARAMETER WorkloadNetworkLabel
            Workload Network label defined in vSphere with Tanzu (default: network-1)
        .PARAMETER WorkloadNetwork
            Workload Network
        .PARAMETER WorkloadNetworkStartIP
            Starting IP Address for Workload VMs
        .PARAMETER WorkloadNetworkIPCount
            Number of IP Addresses to allocate from starting from WorkloadNetworkStartIP
        .PARAMETER WorkloadNetworkSubnet
            Subnet for Workload Network
        .PARAMETER WorkloadNetworkGateway
            Gateway for Workload Network
        .PARAMETER WorkloadNetworkDNS
            DNS Server(s) to use for Workloads
        .PARAMETER WorkloadNetworkServiceCIDR
            K8S Service CIDR (default: 10.96.0.0/24)
        .PARAMETER StoragePolicyName
            Name of VM Storage Policy to use for Control Plane VMs, Ephemeral Disks & Image Cache
        .PARAMETER LoadBalancerLabel
            Load Balancer label defined in vSphere with Tanzu (default: nsx-alb)
        .PARAMETER LoadBalancerStartIP
            Starting IP Address for VIP Load Balancer
        .PARAMETER LoadBalancerIPCount
            Number of IP Addresses to allocate from starting from LoadBalancerStartIP
        .PARAMETER LoginBanner
            Login message to show during kubectl login
        .EXAMPLE
            $vSphereWithTanzuParams = @{
                TanzuvCenterServer = "tanzu-vcsa-1.tshirts.inc";
                TanzuvCenterServerUsername = "administrator@vsphere.local";
                TanzuvCenterServerPassword = "VMware1!";
                ClusterName = "Workload-Cluster";
                TanzuContentLibrary = "TKG-Content-Library";
                ControlPlaneSize = "TINY";
                MgmtNetworkStartIP = "172.17.33.190";
                MgmtNetworkSubnet = "255.255.255.0";
                MgmtNetworkGateway = "172.17.33.1";
                MgmtNetworkDNS = @("172.17.31.2");
                MgmtNetworkDNSDomain = "tshirts.inc";
                MgmtNetworkNTP = @("5.199.135.170");
                WorkloadNetworkStartIP = "172.17.32.160";
                WorkloadNetworkIPCount = 8;
                WorkloadNetworkSubnet = "255.255.255.0";
                WorkloadNetworkGateway = "172.17.32.1";
                WorkloadNetworkDNS = @("172.17.31.2");
                WorkloadNetworkServiceCIDR = "10.96.0.0/24";
                StoragePolicyName = "tanzu-gold-storage-policy";
                NSXALBIPAddress = "172.17.33.9";
                NSXALBPort = "443";
                NSXALBCertName = "nsx-alb"
                NSXALBUsername = "admin";
                NSXALBPassword = "VMware1!";
            }
            New-WorkloadManagement3 @vSphereWithTanzuParams
    #>
    Param (
        [Parameter(Mandatory=$True)]$TanzuvCenterServer,
        [Parameter(Mandatory=$True)]$TanzuvCenterServerUsername,
        [Parameter(Mandatory=$True)]$TanzuvCenterServerPassword,
        [Parameter(Mandatory=$True)]$ClusterName,
        [Parameter(Mandatory=$True)]$TanzuContentLibrary,
        [Parameter(Mandatory=$True)][ValidateSet("TINY","SMALL","MEDIUM","LARGE")][string]$ControlPlaneSize,
        [Parameter(Mandatory=$False)]$MgmtNetwork="DVPG-Supervisor-Management-Network",
        [Parameter(Mandatory=$True)]$MgmtNetworkStartIP,
        [Parameter(Mandatory=$True)]$MgmtNetworkSubnet,
        [Parameter(Mandatory=$True)]$MgmtNetworkGateway,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkDNS,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkDNSDomain,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkNTP,
        [Parameter(Mandatory=$False)][string]$WorkloadNetworkLabel="workload-1",
        [Parameter(Mandatory=$False)][string]$WorkloadNetwork="DVPG-Workload-Network",
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkStartIP,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkIPCount,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkSubnet,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkGateway,
        [Parameter(Mandatory=$True)][string[]]$WorkloadNetworkDNS,
        [Parameter(Mandatory=$False)]$WorkloadNetworkServiceCIDR="10.96.0.0/24",
        [Parameter(Mandatory=$True)][string]$NSXALBIPAddress,
        [Parameter(Mandatory=$True)][string]$NSXALBUsername="admin",
        [Parameter(Mandatory=$True)][string]$NSXALBPassword,
        [Parameter(Mandatory=$False)][string]$NSXALBPort=443,
        [Parameter(Mandatory=$True)][string]$NSXALBCertName="nsx-alb",
        [Parameter(Mandatory=$False)][string]$LoadBalancerLabel="nsx-alb",
        [Parameter(Mandatory=$True)]$StoragePolicyName,
        [Parameter(Mandatory=$False)]$LoginBanner,
        [Switch]$EnableDebug
    )

    # Retrieve TLS certificate from NSX ALB using basic auth

    # Assumes Basic Auth has been enabled per automation below
    $pair = "${NSXALBUsername}:${NSXALBPassword}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)

    $headers = @{
        "Authorization"="basic $base64";
        "Content-Type"="application/json";
        "Accept"="application/json";
        "x-avi-version"="20.1.4";
    }

    try {
        Write-host -ForegroundColor Green "Extracting TLS certificate from NSX ALB ${NSXALBIPAddress} ..."
        $certResult = ((Invoke-WebRequest -Uri https://${NSXALBIPAddress}/api/sslkeyandcertificate?include_name -Method GET -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json).results | where {$_.name -eq $NSXALBCertName}
    } catch {
        Write-Host -ForegroundColor Red "Error in extracting TLS certificate"
        Write-Error "`n($_.Exception.Message)`n"
        break
    }

    $nsxAlbCert = $certResult.certificate.certificate
    if($nsxAlbCert -eq $null) {
        Write-Host -ForegroundColor Red "Unable to locate TLS certificate in NSX ALB named $NSXALBCertName"
        break
    }

    Write-host -ForegroundColor Green "Connecting to Tanzu vCenter Server to enable Workload Management ..."
    Connect-VIServer $TanzuvCenterServer -User $TanzuvCenterServerUsername -Password $TanzuvCenterServerPassword -WarningAction SilentlyContinue | Out-Null

    if( (Get-ContentLibrary -Name $TanzuContentLibrary).syncdate -eq $NULL ) {
        Write-host -ForegroundColor Green "TKG Content Library has not fully sync'ed, please try again later"
        Disconnect-VIServer * -Confirm:$false
        break
    } else {
        Connect-CisServer $TanzuvCenterServer -User $TanzuvCenterServerUsername -Password $TanzuvCenterServerPassword -WarningAction SilentlyContinue | Out-Null

        # Cluster Moref
        $clusterService = Get-CisService "com.vmware.vcenter.cluster"
        $clusterFilterSpec = $clusterService.help.list.filter.Create()
        $clusterFilterSpec.names = @("$ClusterName")
        $clusterMoRef = $clusterService.list($clusterFilterSpec).cluster.Value
        if ($clusterMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Cluster ${ClusterName}"
            break
        }

        # Management Network Moref
        $networkService = Get-CisService "com.vmware.vcenter.network"
        $networkFilterSpec = $networkService.help.list.filter.Create()
        $networkFilterSpec.names = @("$MgmtNetwork")
        $mgmtNetworkMoRef = $networkService.list($networkFilterSpec).network.Value
        if ($mgmtNetworkMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Management Network ${MgmtNetwork}"
            break
        }

        # Workload Network Moref
        $networkFilterSpec = $networkService.help.list.filter.Create()
        $networkFilterSpec.names = @("$WorkloadNetwork")
        $workloadNetworkMoRef = $networkService.list($networkFilterSpec).network.Value
        if ($workloadNetworkMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Workload Network ${WorkloadNetwork}"
            break
        }

        $storagePolicyService = Get-CisService "com.vmware.vcenter.storage.policies"
        $sps= $storagePolicyService.list()
        $pacificSP = ($sps | where {$_.name -eq $StoragePolicyName}).Policy.Value

        $nsmClusterService = Get-CisService "com.vmware.vcenter.namespace_management.clusters"
        $spec = $nsmClusterService.help.enable.spec.Create()

        $networkProvider = "VSPHERE_NETWORK"
        $spec.size_hint = $ControlPlaneSize
        $spec.network_provider = $networkProvider

        # Management Network
        $managementStartRangeSpec = $nsmClusterService.help.enable.spec.master_management_network.address_range.Create()
        $managementStartRangeSpec.starting_address = $MgmtNetworkStartIP
        $managementStartRangeSpec.address_count = 5
        $managementStartRangeSpec.subnet_mask = $MgmtNetworkSubnet
        $managementStartRangeSpec.gateway = $MgmtNetworkGateway

        $mgmtNetworkSpec = $nsmClusterService.help.enable.spec.master_management_network.Create()
        $mgmtNetworkSpec.mode = "STATICRANGE"
        $mgmtNetworkSpec.network =  $mgmtNetworkMoRef
        $mgmtNetworkSpec.address_range = $managementStartRangeSpec

        $spec.master_management_network = $mgmtNetworkSpec

        $spec.master_DNS = @($MgmtNetworkDNS)
        $spec.master_DNS_search_domains = @($MgmtNetworkDNSDomain)
        $spec.master_NTP_servers = @($MgmtNetworkNTP)

        # Workload Network
        $supervisorAddressRangeSpec = $nsmClusterService.help.enable.spec.workload_networks_spec.supervisor_primary_workload_network.vsphere_network.address_ranges.Element.Create()
        $supervisorAddressRangeSpec.address = $WorkloadNetworkStartIP
        $supervisorAddressRangeSpec.count = $WorkloadNetworkIPCount

        $vsphereNetworkSpec = $nsmClusterService.help.enable.spec.workload_networks_spec.supervisor_primary_workload_network.vsphere_network.Create()
        $vsphereNetworkSpec.portgroup = $workloadNetworkMoRef
        $vsphereNetworkSpec.gateway = $WorkloadNetworkGateway
        $vsphereNetworkSpec.subnet_mask = $WorkloadNetworkSubnet
        $vsphereNetworkSpec.address_ranges = @($supervisorAddressRangeSpec)

        $supervisorWorkloadNetworkSpec = $nsmClusterService.help.enable.spec.workload_networks_spec.supervisor_primary_workload_network.Create()
        $supervisorWorkloadNetworkSpec.network = $WorkloadNetworkLabel
        $supervisorWorkloadNetworkSpec.vsphere_network = $vsphereNetworkSpec
        $supervisorWorkloadNetworkSpec.network_provider = $networkProvider

        $workloadNetworksSpec = $nsmClusterService.help.enable.spec.workload_networks_spec.Create()
        $workloadNetworksSpec.supervisor_primary_workload_network = $supervisorWorkloadNetworkSpec
        $spec.workload_networks_spec = $workloadNetworksSpec

        # Load Balancer
        $lbAddressRange = $nsmClusterService.help.enable.spec.load_balancer_config_spec.address_ranges.Element.Create()
        $lbAddressRange.address = "0.0.0.0"
        $lbAddressRange.count = "1"

        $nsxAlbServerSpec = $nsmClusterService.help.enable.spec.load_balancer_config_spec.avi_config_create_spec.server.Create()
        $nsxAlbServerSpec.host = $NSXALBIPAddress
        $nsxAlbServerSpec.port = $NSXALBPort

        $nsxAlbSpec = $nsmClusterService.help.enable.spec.load_balancer_config_spec.avi_config_create_spec.Create()
        $nsxAlbSpec.server = $nsxAlbServerSpec
        $nsxAlbSpec.username = $NSXALBUsername
        $nsxAlbSpec.password = [VMware.VimAutomation.Cis.Core.Types.V1.Secret]$NSXALBPassword
        $nsxAlbSpec.certificate_authority_chain = $nsxAlbCert

        $lbSpec = $nsmClusterService.help.enable.spec.load_balancer_config_spec.Create()
        $lbSpec.id = $LoadBalancerLabel
        $lbSpec.provider = "AVI"
        $lbSpec.avi_config_create_spec = $nsxAlbSpec
        $lbSpec.address_ranges = @($lbAddressRange)

        $spec.load_balancer_config_spec = $lbSpec
        $spec.default_kubernetes_service_content_library = (Get-ContentLibrary -Name $TanzuContentLibrary)[0].id
        $spec.worker_DNS = @($WorkloadNetworkDNS)

        $serviceCidrSpec = $nsmClusterService.help.enable.spec.service_cidr.Create()
        $serviceAddress,$servicePrefix = $WorkloadNetworkServiceCIDR.split("/")
        $serviceCidrSpec.address = $serviceAddress
        $serviceCidrSpec.prefix = $servicePrefix
        $spec.service_cidr = $serviceCidrSpec

        $spec.master_storage_policy = $pacificSP
        $spec.ephemeral_storage_policy = $pacificSP

        $imagePolicySpec = $nsmClusterService.help.enable.spec.image_storage.Create()
        $imagePolicySpec.storage_policy = $pacificSP
        $spec.image_storage = $imagePolicySpec

        $LoginBanner = "

        " + [char]::ConvertFromUtf32(0x1F973) + " vSphere with Tanzu NSX Advanced LB Cluster enabled by William Lam's Script " + [char]::ConvertFromUtf32(0x1F973) + "

    "
        $spec.login_banner = $LoginBanner

        # Output JSON payload
        if($EnableDebug) {
            $spec | ConvertTo-Json -Depth 5
        }

        try {
            Write-host -ForegroundColor Green "Enabling Tanzu Workload Management on vSphere Cluster ${ClusterName} ..."
            $nsmClusterService.enable($clusterMoRef,$spec)
        } catch {
            Write-host -ForegroundColor red "Error in attempting to enable Tanzu Workload Management on vSphere Cluster ${ClusterName}"
            Write-host -ForegroundColor red "($_.Exception.Message)"
            Disconnect-VIServer * -Confirm:$false | Out-Null
            Disconnect-CisServer $global:DefaultCisServers -Confirm:$false | Out-Null
            break
        }
        Write-host -ForegroundColor Green "Please refer to the Tanzu Workload Management UI in vCenter Server to monitor the progress of this operation"

        Write-host -ForegroundColor Green "Disconnecting from Tanzu Management vCenter ..."
        Disconnect-VIServer * -Confirm:$false | Out-Null
        Disconnect-CisServer $global:DefaultCisServers -Confirm:$false | Out-Null
    }
}

Function New-WorkloadManagement2 {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          10/06/2020
        Organization:  VMware
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================

        .SYNOPSIS
            Enable Workload Management on vSphere 7 Cluster using vSphere networking with HAProxy
        .DESCRIPTION
            Enable Workload Management on vSphere 7 Cluster using vSphere networking with HAProxy
        .PARAMETER ClusterName
            Name of vSphere Cluster to enable Workload Management
        .PARAMETER TanzuvCenterServer
            Hostname/IP of the new Tanzu vCenter Server that was deployed
        .PARAMETER TanzuvCenterServerUsername
            Username to connect to new Tanzu vCenter Server
        .PARAMETER TanzuvCenterServerPassword
            Password to connect to new Tanzu vCenter Server
        .PARAMETER TanzuContentLibrary
            Name of the Tanzu Kubernetes Grid subscribed Content Library
        .PARAMETER ControlPlaneSize
            Size of Control Plane VMs (TINY, SMALL, MEDIUM, LARGE)
        .PARAMETER HAProxyVMName
            The display name of the HAProxy VM
        .PARAMETER HAProxyRootPassword
            Root password for HAProxy VM
        .PARAMETER HAProxyUsername
            HAProxy Control Plane Username (default: wcp)
        .PARAMETER HAProxyPassword
            HAProxy Control Plane Password
        .PARAMETER HAProxyIPAddress
            HAProxy VM Control Plane IP Address
        .PARAMETER HAProxyPort
            HAProxy Control Plane port (default: 5556)
        .PARAMETER HAProxyVMvCenterServer
            Hostname/IP of the vCenter Server managing HAProxy VM to automatically retrieve CA certificate
        .PARAMETER HAProxyVMvCenterUsername
            Username to connect to vCenter Server managing HAProxy VM to automatically retrieve CA certificate
        .PARAMETER HAProxyVMvCenterPassword
            Password to connect to vCenter Server managing HAProxy VM to automatically retrieve CA certificate
        .PARAMETER MgmtNetwork
            Supervisor Management Network for Control Plane VMs
        .PARAMETER MgmtNetworkStartIP
            Starting IP Address for Control Plane VMs (5 consecutive free addresses)
        .PARAMETER MgmtNetworkSubnet
            Netmask for Management Network
        .PARAMETER MgmtNetworkGateway
            Gateway for Management Network
        .PARAMETER MgmtNetworkDNS
            DNS Server(s) to use for Management Network
        .PARAMETER MgmtNetworkDNSDomain
            DNS Domain(s)
        .PARAMETER MgmtNetworkNTP
            NTP Server(s)
        .PARAMETER WorkloadNetworkLabel
            Workload Network label defined in vSphere with Tanzu (default: network-1)
        .PARAMETER WorkloadNetwork
            Workload Network
        .PARAMETER WorkloadNetworkStartIP
            Starting IP Address for Workload VMs
        .PARAMETER WorkloadNetworkIPCount
            Number of IP Addresses to allocate from starting from WorkloadNetworkStartIP
        .PARAMETER WorkloadNetworkSubnet
            Subnet for Workload Network
        .PARAMETER WorkloadNetworkGateway
            Gateway for Workload Network
        .PARAMETER WorkloadNetworkDNS
            DNS Server(s) to use for Workloads
        .PARAMETER WorkloadNetworkServiceCIDR
            K8S Service CIDR (default: 10.96.0.0/24)
        .PARAMETER StoragePolicyName
            Name of VM Storage Policy to use for Control Plane VMs, Ephemeral Disks & Image Cache
        .PARAMETER LoadBalancerLabel
            Load Balancer label defined in vSphere with Tanzu (default: tanzu-haproxy-1)
        .PARAMETER LoadBalancerStartIP
            Starting IP Address for HAProxy Load Balancer
        .PARAMETER LoadBalancerIPCount
            Number of IP Addresses to allocate from starting from LoadBalancerStartIP
        .PARAMETER LoginBanner
            Login message to show during kubectl login
        .EXAMPLE
            $vSphereWithTanzuParams = @{
                ClusterName = "Workload-Cluster";
                TanzuvCenterServer = "tanzu-vcsa-1.cpbu.corp";
                TanzuvCenterServerUsername = "administrator@vsphere.local";
                TanzuvCenterServerPassword = "VMware1!";
                TanzuContentLibrary = "TKG-Content-Library";
                ControlPlaneSize = "TINY";
                HAProxyVMName = "tanzu-haproxy-1";
                HAProxyIPAddress = "172.17.31.116";
                HAProxyRootPassword = "VMware1!";
                HAProxyUsername = "wcp";
                HAProxyPassword = "VMware1!";
                MgmtNetworkStartIP = "172.17.31.120";
                MgmtNetworkSubnet = "255.255.255.0";
                MgmtNetworkGateway = "172.17.31.1";
                MgmtNetworkDNS = @("172.17.31.5");
                MgmtNetworkDNSDomain = "cpbu.corp";
                MgmtNetworkNTP = @("5.199.135.170");
                WorkloadNetworkStartIP = "172.17.36.130";
                WorkloadNetworkIPCount = 20;
                WorkloadNetworkSubnet = "255.255.255.0";
                WorkloadNetworkGateway = "172.17.36.1";
                WorkloadNetworkDNS = @("172.17.31.5");
                WorkloadNetworkServiceCIDR = "10.96.0.0/24";
                StoragePolicyName = "tanzu-gold-storage-policy";
                HAProxyVMvCenterServer = "mgmt-vcsa-01.cpbu.corp";
                HAProxyVMvCenterUsername = "administrator@vsphere.local";
                HAProxyVMvCenterPassword = "VMware1!";
                LoadBalancerStartIP = "172.17.36.2";
                LoadBalancerIPCount = 125
            }
            New-WorkloadManagement2 @vSphereWithTanzuParams
    #>
    Param (
        [Parameter(Mandatory=$True)]$HAProxyVMName,
        [Parameter(Mandatory=$True)]$HAProxyRootPassword,
        [Parameter(Mandatory=$False)]$HAProxyUsername="wcp",
        [Parameter(Mandatory=$True)]$HAProxyPassword,
        [Parameter(Mandatory=$True)]$HAProxyVMvCenterServer,
        [Parameter(Mandatory=$True)]$HAProxyVMvCenterUsername,
        [Parameter(Mandatory=$True)]$HAProxyVMvCenterPassword,
        [Parameter(Mandatory=$True)]$TanzuvCenterServer,
        [Parameter(Mandatory=$True)]$TanzuvCenterServerUsername,
        [Parameter(Mandatory=$True)]$TanzuvCenterServerPassword,
        [Parameter(Mandatory=$True)]$ClusterName,
        [Parameter(Mandatory=$True)]$TanzuContentLibrary,
        [Parameter(Mandatory=$True)][ValidateSet("TINY","SMALL","MEDIUM","LARGE")][string]$ControlPlaneSize,
        [Parameter(Mandatory=$False)]$MgmtNetwork="DVPG-Supervisor-Management-Network",
        [Parameter(Mandatory=$True)]$MgmtNetworkStartIP,
        [Parameter(Mandatory=$True)]$MgmtNetworkSubnet,
        [Parameter(Mandatory=$True)]$MgmtNetworkGateway,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkDNS,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkDNSDomain,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkNTP,
        [Parameter(Mandatory=$False)][string]$WorkloadNetworkLabel="workload-1",
        [Parameter(Mandatory=$False)][string]$WorkloadNetwork="DVPG-Workload-Network",
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkStartIP,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkIPCount,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkSubnet,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkGateway,
        [Parameter(Mandatory=$True)][string[]]$WorkloadNetworkDNS,
        [Parameter(Mandatory=$False)]$WorkloadNetworkServiceCIDR="10.96.0.0/24",
        [Parameter(Mandatory=$False)][string]$LoadBalancerLabel="tanzu-haproxy-1",
        [Parameter(Mandatory=$True)][string]$HAProxyIPAddress,
        [Parameter(Mandatory=$False)][string]$HAProxyPort=5556,
        [Parameter(Mandatory=$True)][string]$LoadBalancerStartIP,
        [Parameter(Mandatory=$True)][string]$LoadBalancerIPCount,
        [Parameter(Mandatory=$True)]$StoragePolicyName,
        [Parameter(Mandatory=$False)]$LoginBanner,
        [Switch]$EnableDebug
    )

    Write-host -ForegroundColor Green "Connecting to Management vCenter Server $HAProxyVMvCenterServer to retrieve HAProxy CA Certificate ..."
    $viConnection = Connect-VIServer $HAProxyVMvCenterServer -User $HAProxyVMvCenterUsername -Password $HAProxyVMvCenterPassword -WarningAction SilentlyContinue
    $caCertCmd = "cat /etc/haproxy/ca.crt"
    $haProxyCert = (Invoke-VMScript -Server $viConnection -ScriptText $caCertCmd -vm (Get-VM -Server $viConnection -Name $HAProxyVMName) -GuestUser "root" -GuestPassword "$HAProxyRootPassword").ScriptOutput

    Write-host -ForegroundColor Green "Disconnecting from Management vCenter ..."
    Disconnect-VIServer $viConnection -Confirm:$false

    Write-host -ForegroundColor Green "Connecting to Tanzu vCenter Server to enable Workload Management ..."
    Connect-VIServer $TanzuvCenterServer -User $TanzuvCenterServerUsername -Password $TanzuvCenterServerPassword -WarningAction SilentlyContinue | Out-Null

    if( (Get-ContentLibrary -Name $TanzuContentLibrary).syncdate -eq $NULL ) {
        Write-host -ForegroundColor Green "TKG Content Library has not fully sync'ed, please try again later"
        Disconnect-VIServer * -Confirm:$false
        break
    } else {
        Connect-CisServer $TanzuvCenterServer -User $TanzuvCenterServerUsername -Password $TanzuvCenterServerPassword -WarningAction SilentlyContinue | Out-Null

        # Cluster Moref
        $clusterService = Get-CisService "com.vmware.vcenter.cluster"
        $clusterFilterSpec = $clusterService.help.list.filter.Create()
        $clusterFilterSpec.names = @("$ClusterName")
        $clusterMoRef = $clusterService.list($clusterFilterSpec).cluster.Value
        if ($clusterMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Cluster ${ClusterName}"
            break
        }

        # Management Network Moref
        $networkService = Get-CisService "com.vmware.vcenter.network"
        $networkFilterSpec = $networkService.help.list.filter.Create()
        $networkFilterSpec.names = @("$MgmtNetwork")
        $mgmtNetworkMoRef = $networkService.list($networkFilterSpec).network.Value
        if ($mgmtNetworkMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Management Network ${MgmtNetwork}"
            break
        }

        # Workload Network Moref
        $networkFilterSpec = $networkService.help.list.filter.Create()
        $networkFilterSpec.names = @("$WorkloadNetwork")
        $workloadNetworkMoRef = $networkService.list($networkFilterSpec).network.Value
        if ($workloadNetworkMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Workload Network ${WorkloadNetwork}"
            break
        }

        $storagePolicyService = Get-CisService "com.vmware.vcenter.storage.policies"
        $sps= $storagePolicyService.list()
        $pacificSP = ($sps | where {$_.name -eq $StoragePolicyName}).Policy.Value

        $nsmClusterService = Get-CisService "com.vmware.vcenter.namespace_management.clusters"
        $spec = $nsmClusterService.help.enable.spec.Create()

        $networkProvider = "VSPHERE_NETWORK"
        $spec.size_hint = $ControlPlaneSize
        $spec.network_provider = $networkProvider

        # Management Network
        $managementStartRangeSpec = $nsmClusterService.help.enable.spec.master_management_network.address_range.Create()
        $managementStartRangeSpec.starting_address = $MgmtNetworkStartIP
        $managementStartRangeSpec.address_count = 5
        $managementStartRangeSpec.subnet_mask = $MgmtNetworkSubnet
        $managementStartRangeSpec.gateway = $MgmtNetworkGateway

        $mgmtNetworkSpec = $nsmClusterService.help.enable.spec.master_management_network.Create()
        $mgmtNetworkSpec.mode = "STATICRANGE"
        $mgmtNetworkSpec.network =  $mgmtNetworkMoRef
        $mgmtNetworkSpec.address_range = $managementStartRangeSpec

        $spec.master_management_network = $mgmtNetworkSpec

        $spec.master_DNS = @($MgmtNetworkDNS)
        $spec.master_DNS_search_domains = @($MgmtNetworkDNSDomain)
        $spec.master_NTP_servers = @($MgmtNetworkNTP)

        # Workload Network
        $supervisorAddressRangeSpec = $nsmClusterService.help.enable.spec.workload_networks_spec.supervisor_primary_workload_network.vsphere_network.address_ranges.Element.Create()
        $supervisorAddressRangeSpec.address = $WorkloadNetworkStartIP
        $supervisorAddressRangeSpec.count = $WorkloadNetworkIPCount

        $vsphereNetworkSpec = $nsmClusterService.help.enable.spec.workload_networks_spec.supervisor_primary_workload_network.vsphere_network.Create()
        $vsphereNetworkSpec.portgroup = $workloadNetworkMoRef
        $vsphereNetworkSpec.gateway = $WorkloadNetworkGateway
        $vsphereNetworkSpec.subnet_mask = $WorkloadNetworkSubnet
        $vsphereNetworkSpec.address_ranges = @($supervisorAddressRangeSpec)

        $supervisorWorkloadNetworkSpec = $nsmClusterService.help.enable.spec.workload_networks_spec.supervisor_primary_workload_network.Create()
        $supervisorWorkloadNetworkSpec.network = $WorkloadNetworkLabel
        $supervisorWorkloadNetworkSpec.vsphere_network = $vsphereNetworkSpec
        $supervisorWorkloadNetworkSpec.network_provider = $networkProvider

        $workloadNetworksSpec = $nsmClusterService.help.enable.spec.workload_networks_spec.Create()
        $workloadNetworksSpec.supervisor_primary_workload_network = $supervisorWorkloadNetworkSpec
        $spec.workload_networks_spec = $workloadNetworksSpec

        # Load Balancer
        $lbAddressRange = $nsmClusterService.help.enable.spec.load_balancer_config_spec.address_ranges.Element.Create()
        $lbAddressRange.address = $LoadBalancerStartIP
        $lbAddressRange.count = $LoadBalancerIPCount

        $haProxyServerSpec = $nsmClusterService.help.enable.spec.load_balancer_config_spec.ha_proxy_config_create_spec.servers.Element.Create()
        $haProxyServerSpec.host = $HAProxyIPAddress
        $haProxyServerSpec.port = $HAProxyPort

        $haProxySpec = $nsmClusterService.help.enable.spec.load_balancer_config_spec.ha_proxy_config_create_spec.Create()
        $haProxySpec.username = $HAProxyUsername
        $haProxySpec.password = [VMware.VimAutomation.Cis.Core.Types.V1.Secret]$HAProxyPassword
        $haProxySpec.certificate_authority_chain = $haProxyCert
        $haProxySpec.servers = @($haProxyServerSpec)

        $lbSpec = $nsmClusterService.help.enable.spec.load_balancer_config_spec.Create()
        $lbSpec.id = $LoadBalancerLabel
        $lbSpec.provider = "HA_PROXY"
        $lbSpec.ha_proxy_config_create_spec = $haProxySpec
        $lbSpec.address_ranges = @($lbAddressRange)

        $spec.load_balancer_config_spec = $lbSpec
        $spec.default_kubernetes_service_content_library = (Get-ContentLibrary -Name $TanzuContentLibrary)[0].id
        $spec.worker_DNS = @($WorkloadNetworkDNS)

        $serviceCidrSpec = $nsmClusterService.help.enable.spec.service_cidr.Create()
        $serviceAddress,$servicePrefix = $WorkloadNetworkServiceCIDR.split("/")
        $serviceCidrSpec.address = $serviceAddress
        $serviceCidrSpec.prefix = $servicePrefix
        $spec.service_cidr = $serviceCidrSpec

        $spec.master_storage_policy = $pacificSP
        $spec.ephemeral_storage_policy = $pacificSP

        $imagePolicySpec = $nsmClusterService.help.enable.spec.image_storage.Create()
        $imagePolicySpec.storage_policy = $pacificSP
        $spec.image_storage = $imagePolicySpec

        $LoginBanner = "

        " + [char]::ConvertFromUtf32(0x1F973) + " vSphere with Tanzu Basic Cluster enabled by William Lam's Script " + [char]::ConvertFromUtf32(0x1F973) + "

    "
        $spec.login_banner = $LoginBanner

        # Output JSON payload
        if($EnableDebug) {
            $spec | ConvertTo-Json -Depth 5
        }

        try {
            Write-host -ForegroundColor Green "Enabling Tanzu Workload Management on vSphere Cluster ${ClusterName} ..."
            $nsmClusterService.enable($clusterMoRef,$spec)
        } catch {
            Write-host -ForegroundColor red "Error in attempting to enable Tanzu Workload Management on vSphere Cluster ${ClusterName}"
            Write-host -ForegroundColor red "($_.Exception.Message)"
            Disconnect-VIServer * -Confirm:$false | Out-Null
            Disconnect-CisServer $global:DefaultCisServers -Confirm:$false | Out-Null
            break
        }
        Write-host -ForegroundColor Green "Please refer to the Tanzu Workload Management UI in vCenter Server to monitor the progress of this operation"

        Write-host -ForegroundColor Green "Disconnecting from Tanzu Management vCenter ..."
        Disconnect-VIServer * -Confirm:$false | Out-Null
        Disconnect-CisServer $global:DefaultCisServers -Confirm:$false | Out-Null
    }
}

Function New-WorkloadManagement {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          05/19/2020
        Organization:  VMware
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================

        .SYNOPSIS
            Enable Workload Management on vSphere 7 Cluster using NSX-T networking
        .DESCRIPTION
            Enable Workload Management on vSphere 7 Cluster using NSX-T networking
        .PARAMETER ClusterName
            Name of vSphere Cluster to enable Workload Management
        .PARAMETER ControlPlaneSize
            Size of Control Plane VMs (TINY, SMALL, MEDIUM, LARGE)
        .PARAMETER MgmtNetwork
            Management Network for Control Plane VMs
        .PARAMETER MgmtNetworkStartIP
            Starting IP Address for Control Plane VMs (5 consecutive free addresses)
        .PARAMETER MgmtNetworkSubnet
            Netmask for Management Network
        .PARAMETER MgmtNetworkGateway
            Gateway for Management Network
        .PARAMETER MgmtNetworkDNS
            DNS Server(s) to use for Management Network
        .PARAMETER MgmtNetworkDNSDomain
            DNS Domain(s)
        .PARAMETER MgmtNetworkNTP
            NTP Server(s)
        .PARAMETER WorkloadNetworkVDS
            Name of vSphere 7 Distributed Virtual Switch (VDS) configured with NSX-T
        .PARAMETER WorkloadNetworkEdgeCluster
            Name of NSX-T Edge Cluster
        .PARAMETER WorkloadNetworkDNS
            DNS Server(s) to use for Workloads
        .PARAMETER WorkloadNetworkPodCIDR
            K8s POD CIDR (default: 10.244.0.0/21)
        .PARAMETER WorkloadNetworkServiceCIDR
            K8S Service CIDR (default: 10.96.0.0/24)
        .PARAMETER WorkloadNetworkIngressCIDR
            CIDR for Workload Ingress (recommend /27 or larger)
        .PARAMETER WorkloadNetworkEgressCIDR
            CIDR for Workload Egress (recommend /27 or larger)
        .PARAMETER ControlPlaneStoragePolicy
            Name of VM Storage Policy to use for Control Plane VMs
        .PARAMETER EphemeralDiskStoragePolicy
            Name of VM Storage Policy to use for Ephemeral Disk
        .PARAMETER ImageCacheStoragePolicy
            Name of VM Storage Policy to use for Image Cache
        .PARAMETER LoginBanner
            Login message to show during kubectl login
        .EXAMPLE
            New-WorkloadManagement `
                -ClusterName "Workload-Cluster" `
                -ControlPlaneSize TINY `
                -MgmtNetwork "DVPG-Management Network" `
                -MgmtNetworkStartIP "172.17.33.150" `
                -MgmtNetworkSubnet "255.255.255.0" `
                -MgmtNetworkGateway "172.17.33.1" `
                -MgmtNetworkDNS "172.17.31.2" `
                -MgmtNetworkDNSDomain "tshirts.inc" `
                -MgmtNetworkNTP "5.199.135.170" `
                -WorkloadNetworkVDS "Tanzu-VDS" `
                -WorkloadNetworkEdgeCluster "Edge-Cluster-01" `
                -WorkloadNetworkDNS "172.17.31.2" `
                -WorkloadNetworkIngressCIDR "172.17.33.64/27" `
                -WorkloadNetworkEgressCIDR "172.17.33.160/27" `
                -ControlPlaneStoragePolicy "tanzu-gold-storage-policy" `
                -EphemeralDiskStoragePolicy "tanzu-gold-storage-policy" `
                -ImageCacheStoragePolicy "tanzu-gold-storage-policy"

    #>
    Param (
        [Parameter(Mandatory=$True)]$ClusterName,
        [Parameter(Mandatory=$True)][ValidateSet("TINY","SMALL","MEDIUM","LARGE")][string]$ControlPlaneSize,
        [Parameter(Mandatory=$True)]$MgmtNetwork,
        [Parameter(Mandatory=$True)]$MgmtNetworkStartIP,
        [Parameter(Mandatory=$True)]$MgmtNetworkSubnet,
        [Parameter(Mandatory=$True)]$MgmtNetworkGateway,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkDNS,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkDNSDomain,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkNTP,
        [Parameter(Mandatory=$True)]$WorkloadNetworkVDS,
        [Parameter(Mandatory=$True)]$WorkloadNetworkEdgeCluster,
        [Parameter(Mandatory=$True)][string[]]$WorkloadNetworkDNS,
        [Parameter(Mandatory=$False)]$WorkloadNetworkPodCIDR="10.244.0.0/21",
        [Parameter(Mandatory=$False)]$WorkloadNetworkServiceCIDR="10.96.0.0/24",
        [Parameter(Mandatory=$True)]$WorkloadNetworkIngressCIDR,
        [Parameter(Mandatory=$True)]$WorkloadNetworkEgressCIDR,
        [Parameter(Mandatory=$True)]$ControlPlaneStoragePolicy,
        [Parameter(Mandatory=$True)]$EphemeralDiskStoragePolicy,
        [Parameter(Mandatory=$True)]$ImageCacheStoragePolicy,
        [Parameter(Mandatory=$False)]$LoginBanner
    )

    If (-Not $global:DefaultCisServers) { Write-error "No CiS Connection found, please use Connect-CisServer`n" } Else {

        # Management Network Moref
        $networkService = Get-CisService "com.vmware.vcenter.network"
        $networkFilterSpec = $networkService.help.list.filter.Create()
        $networkFilterSpec.names = @("$MgmtNetwork")
        $mgmtNetworkMoRef = $networkService.list($networkFilterSpec).network.Value
        if ($mgmtNetworkMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Cluster ${MgmtNetwork}"
            break 
        }

        # Cluster Moref
        $clusterService = Get-CisService "com.vmware.vcenter.cluster"
        $clusterFilterSpec = $clusterService.help.list.filter.Create()
        $clusterFilterSpec.names = @("$ClusterName")
        $clusterMoRef = $clusterService.list($clusterFilterSpec).cluster.Value
        if ($clusterMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Cluster ${ClusterName}"
            break
        }

        # VDS MoRef
        $vdsCompatService = Get-CisService "com.vmware.vcenter.namespace_management.distributed_switch_compatibility"
        $vdsMoRef = ($vdsCompatService.list($clusterMoref)).distributed_switch.Value
        if ($vdsMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find VDS ${WorkloadNetworkVDS}"
            break
        }

        # NSX-T Edge Cluster
        $edgeClusterService = Get-CisService "com.vmware.vcenter.namespace_management.edge_cluster_compatibility"
        $edgeClusterMoRef = ($edgeClusterService.list($clusterMoref,$vdsMoRef)).edge_cluster.Value
        if ($edgeClusterMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find NSX-T Edge Cluster ${WorkloadNetworkEdgeCluster}"
            break
        }

        # VM Storage Policy MoRef
        $storagePolicyService = Get-CisService "com.vmware.vcenter.storage.policies"
        $sps= $storagePolicyService.list()
        $cpSP = ($sps | where {$_.name -eq $ControlPlaneStoragePolicy}).Policy.Value
        $edSP = ($sps | where {$_.name -eq $EphemeralDiskStoragePolicy}).Policy.Value
        $icSP = ($sps | where {$_.name -eq $ImageCacheStoragePolicy}).Policy.Value
        if ($cpSP -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find VM Storage Policy ${ControlPlaneStoragePolicy}"
            break
        }

        if ($edSP -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find VM Storage Policy ${EphemeralDiskStoragePolicy}"
            break
        }

        if ($icSP -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find VM Storage Policy ${ImageCacheStoragePolicy}"
            break
        }

        $nsmClusterService = Get-CisService "com.vmware.vcenter.namespace_management.clusters"
        $spec = $nsmClusterService.help.enable.spec.Create()

        $spec.size_hint = $ControlPlaneSize
        $spec.network_provider = "NSXT_CONTAINER_PLUGIN"

        $mgmtNetworkSpec = $nsmClusterService.help.enable.spec.master_management_network.Create()
        $mgmtNetworkSpec.mode = "STATICRANGE"
        $mgmtNetworkSpec.network =  $mgmtNetworkMoRef
        $mgmtNetworkSpec.address_range.starting_address = $MgmtNetworkStartIP
        $mgmtNetworkSpec.address_range.address_count = 5
        $mgmtNetworkSpec.address_range.subnet_mask = $MgmtNetworkSubnet
        $mgmtNetworkSpec.address_range.gateway = $MgmtNetworkGateway

        $spec.master_management_network = $mgmtNetworkSpec
        $spec.master_DNS = $MgmtNetworkDNS
        $spec.master_DNS_search_domains = $MgmtNetworkDNSDomain
        $spec.master_NTP_servers = $MgmtNetworkNTP

        $spec.ncp_cluster_network_spec.cluster_distributed_switch = $vdsMoRef
        $spec.ncp_cluster_network_spec.nsx_edge_cluster = $edgeClusterMoRef

        $spec.worker_DNS = $WorkloadNetworkDNS

        $serviceCidrSpec = $nsmClusterService.help.enable.spec.service_cidr.Create()
        $serviceAddress,$servicePrefix = $WorkloadNetworkServiceCIDR.split("/")
        $serviceCidrSpec.address = $serviceAddress
        $serviceCidrSpec.prefix = $servicePrefix
        $spec.service_cidr = $serviceCidrSpec

        $podCidrSpec = $nsmClusterService.help.enable.spec.ncp_cluster_network_spec.pod_cidrs.Element.Create()
        $podAddress,$podPrefix = $WorkloadNetworkPodCIDR.split("/")
        $podCidrSpec.address = $podAddress
        $podCidrSpec.prefix = $podPrefix
        $spec.ncp_cluster_network_spec.pod_cidrs = @($podCidrSpec)

        $egressCidrSpec = $nsmClusterService.help.enable.spec.ncp_cluster_network_spec.egress_cidrs.Element.Create()
        $egressAddress,$egressPrefix = $WorkloadNetworkEgressCIDR.split("/")
        $egressCidrSpec.address = $egressAddress
        $egressCidrSpec.prefix = $egressPrefix
        $spec.ncp_cluster_network_spec.egress_cidrs = @($egressCidrSpec)

        $ingressCidrSpec = $nsmClusterService.help.enable.spec.ncp_cluster_network_spec.ingress_cidrs.Element.Create()
        $ingressAddress,$ingressPrefix = $WorkloadNetworkIngressCIDR.split("/")
        $ingressCidrSpec.address = $ingressAddress
        $ingressCidrSpec.prefix = $ingressPrefix
        $spec.ncp_cluster_network_spec.ingress_cidrs = @($ingressCidrSpec)

        $spec.master_storage_policy = $cpSP
        $spec.ephemeral_storage_policy = $edSP

        $imagePolicySpec = $nsmClusterService.help.enable.spec.image_storage.Create()
        $imagePolicySpec.storage_policy = $icSP
        $spec.image_storage = $imagePolicySpec

        if($LoginBanner -eq $NULL) {
            $LoginBanner = "

            " + [char]::ConvertFromUtf32(0x1F973) + " vSphere with Tanzu Cluster enabled by William Lam's Script " + [char]::ConvertFromUtf32(0x1F973) + "

"
        }
        $spec.login_banner = $LoginBanner

        try {
            Write-Host -Foreground Green "`nEnabling Workload Management on vSphere Cluster ${ClusterName} ..."
            $nsmClusterService.enable($clusterMoRef,$spec)
        } catch {
            Write-Error "Error in attempting to enable Workload Management on vSphere Cluster ${ClusterName}"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
        Write-Host -Foreground Green "Please refer to the Workload Management UI in vCenter Server to monitor the progress of this operation"
    }
}

Function Get-WorkloadManagement {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          05/19/2020
        Organization:  VMware
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================

        .SYNOPSIS
            Retrieve all Workload Management Clusters
        .DESCRIPTION
            Retrieve all Workload Management Clusters
        .PARAMETER Stats
            Output additional stats pertaining to CPU, Memory and Storage
        .EXAMPLE
            Get-WorkloadManagement
        .EXAMPLE
            Get-WorkloadManagement -Stats
    #>
    Param (
        [Switch]$Stats
    )

    If (-Not $global:DefaultCisServers) { Write-error "No CiS Connection found, please use Connect-CisServer`n" } Else {
        If (-Not $global:DefaultVIServers) { Write-error "No VI Connection found, please use Connect-VIServer`n" } Else {
            $nssClusterService = Get-CisService "com.vmware.vcenter.namespace_management.software.clusters"
            $nsInstanceService = Get-CisService "com.vmware.vcenter.namespaces.instances"
            $nsmClusterService = Get-CisService "com.vmware.vcenter.namespace_management.clusters"
            $wlClusters = $nsmClusterService.list()

            $results = @()
            foreach ($wlCluster in $wlClusters) {
                $workloadClusterId = $wlCluster.cluster
                $vSphereCluster = Get-Cluster | where {$_.id -eq "ClusterComputeResource-${workloadClusterId}"}
                $workloadCluster = $nsmClusterService.get($workloadClusterId)

                $nsCount = ($nsInstanceService.list() | where {$_.cluster -eq $workloadClusterId}).count
                $hostCount = ($vSphereCluster | Get-VMHost).count
                if($workloadCluster.kubernetes_status -ne "ERROR") {
                $k8sVersion = $nssClusterService.get($workloadClusterId).current_version
                } else { $k8sVersion = "UNKNOWN" }

                $tmp = [pscustomobject] @{
                    NAME = $vSphereCluster.name;
                    NAMESPACES = $nsCount;
                    HOSTS = $hostCount;
                    CONTROL_PLANE_IP = $workloadCluster.api_server_cluster_endpoint;
                    CLUSTER_STATUS = $workloadCluster.config_status;
                    K8S_STATUS = $workloadCluster.kubernetes_status;
                    VERSION = $k8sVersion;
                }

                if($Stats) {
                    $tmp | Add-Member -NotePropertyName CPU_CAPACITY -NotePropertyValue $workloadCluster.stat_summary.cpu_capacity
                    $tmp | Add-Member -NotePropertyName MEM_CAPACITY -NotePropertyValue $workloadCluster.stat_summary.memory_capacity
                    $tmp | Add-Member -NotePropertyName STORAGE_CAPACITY -NotePropertyValue $workloadCluster.stat_summary.storage_capacity
                    $tmp | Add-Member -NotePropertyName CPU_USED -NotePropertyValue $workloadCluster.stat_summary.cpu_used
                    $tmp | Add-Member -NotePropertyName MEM_USED -NotePropertyValue $workloadCluster.stat_summary.memory_used
                    $tmp | Add-Member -NotePropertyName STORAGE_USED -NotePropertyValue $workloadCluster.stat_summary.storage_used
                }

                $results+=$tmp
            }
            $results
        }
    }
}

Function Remove-WorkloadManagement {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          05/19/2020
        Organization:  VMware
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================

        .SYNOPSIS
            Disable Workload Management on vSphere Cluster
        .DESCRIPTION
            Disable Workload Management on vSphere Cluster
        .PARAMETER ClusterName
            Name of vSphere Cluster to disable Workload Management
        .EXAMPLE
            Remove-WorkloadManagement -ClusterName "Workload-Cluster"
    #>
    Param (
        [Parameter(Mandatory=$True)]$ClusterName
    )

    If (-Not $global:DefaultCisServers) { Write-error "No CiS Connection found, please use Connect-CisServer`n" } Else {

        $vSphereCluster = Get-Cluster | where {$_.Name -eq $ClusterName}
        if($vSphereCluster -eq $null) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Cluster ${ClusterName}"
            break
        }
        $vSphereClusterID = ($vSphereCluster.id).replace("ClusterComputeResource-","")

        $nsmClusterService = Get-CisService "com.vmware.vcenter.namespace_management.clusters"
        $workloadClusterID = ($nsmClusterService.list() | where {$_.cluster -eq $vSphereClusterID}).cluster.Value
        if($workloadClusterID -eq $null) {
            Write-Host -ForegroundColor Red "Unable to find Workload Management Cluster ${ClusterName}"
            break
        }

        try {
            Write-Host -Foreground Green "`nDisabling Workload Management on vSphere Cluster ${ClusterName} ..."
            $nsmClusterService.disable($workloadClusterID)
        } catch {
            Write-Error "Error in attempting to disable Workload Management on vSphere Cluster ${ClusterName}"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
        Write-Host -Foreground Green "Please refer to the Workload Management UI in vCenter Server to monitor the progress of this operation"
    }
}
