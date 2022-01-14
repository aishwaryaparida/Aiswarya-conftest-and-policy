package openshift.policy 

deny[msg]
{
    input.kind == "Deployment"
    containers := input.spec.template.spec.containers[_]
    containers.securityContext.allowPriviledgeEscalation
    msg := sprintf("POLICY FAILED : can't allow priviledged escalation enabled containers for container %s",[containers.name])
}