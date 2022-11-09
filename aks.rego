package terraform.azure

deny_ckv_azure_115 [msg] {
    r := after_resource("azurerm_kubernetes_cluster")
    r.change.after.private_cluster_enabled == false
    msg := sprintf("CKV_Azure_115 AKS is not enabled for private clusters: %s", [r.address])
}

deny_ckv_azure_7 [msg] {
    r := after_resource("azurerm_kubernetes_cluster")
    r.change.after.network_profile[_].network_plugin != "azure"
    msg := sprintf("CKV_AZURE_7 %s should use \"azure\" network_plugin", [r.address])
}

role_based_access_control_disabled(i) = r {
    r := i.role_based_access_control_enabled != true
}

role_based_access_control_disabled(i) = r {
    r := i.role_based_access_control[_].enabled != true
}

deny_ckv_azure_5 [msg] {
    r := after_resource("azurerm_kubernetes_cluster")
    after := r.change.after
    role_based_access_control_disabled(after)
    msg := sprintf("CKV_AZURE_5 %s should ensure Azure AKS enable RBAC is enforced", [r.address])
}

aks_log_analytics_workspace_on(i) = r {
    r := i.after.addon_profile[_].oms_agent[_].enabled == true
}

aks_log_analytics_workspace_on(i) = r {
    log_id := i.after.oms_agent[_].log_analytics_workspace_id
    r := regex.match("/subscriptions/.+/resourceGroups/.+/providers/Microsoft.OperationalInsights/workspaces/.+", log_id)
}

aks_log_analytics_workspace_on(i) = r {
    r := i.after_unknown.oms_agent[_].log_analytics_workspace_id == true
}

deny_ckv_azure_4 [msg] {
    r := after_resource("azurerm_kubernetes_cluster")
    not aks_log_analytics_workspace_on(r.change)
    msg := sprintf("CKV_AZURE_4 %s Azure AKS cluster monitoring is not enabled", [r.address])
}

deny_ckv_azure_116 [msg] {
    r := after_resource("azurerm_kubernetes_cluster")
    r.change.after.azure_policy_enabled != true
    msg := sprintf("CKV_AZURE_116 %s Ensure AKS policies add-on", [r.address])
}

has_disk_encryption_set(i) = r {
    disk_encryption_set_id := i.after.disk_encryption_set_id
    r := regex.match("/subscriptions/.+/resourceGroups/.+/providers/Microsoft.Compute/diskEncryptionSets/.+", disk_encryption_set_id)
}

has_disk_encryption_set(i) = r {
    r := i.after_unknown.disk_encryption_set_id == true
}

deny_ckv_azure_117 [msg] {
    r := after_resource("azurerm_kubernetes_cluster")
    not has_disk_encryption_set(r.change)
    msg := sprintf("CKV_AZURE_117 %s Ensure that AKS uses disk encryption set", [r.address])
}