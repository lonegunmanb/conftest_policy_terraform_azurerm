package terraform.azure

after_resource(type) = r {
    r := input.resource_changes[_]
    r.mode == "managed"
    r.type == type
}