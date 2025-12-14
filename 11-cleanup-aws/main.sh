#!/bin/bash

# AWS Resource Cleanup Script
# Deletes all resources in a specific AWS region
# USE WITH EXTREME CAUTION - This is destructive and irreversible!

set -e

# Configuration
REGION="${1:-us-east-1}"
DRY_RUN="${2:-true}"  # Set to "false" to actually delete

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}============================================${NC}"
echo -e "${RED}  AWS RESOURCE DELETION SCRIPT${NC}"
echo -e "${RED}  Region: ${REGION}${NC}"
echo -e "${RED}  Dry Run: ${DRY_RUN}${NC}"
echo -e "${RED}============================================${NC}"

if [ "$DRY_RUN" == "false" ]; then
    echo -e "${RED}WARNING: This will PERMANENTLY DELETE all resources!${NC}"
    read -p "Type 'DELETE' to confirm: " confirm
    [ "$confirm" != "DELETE" ] && echo "Aborted." && exit 1
fi

run_cmd() {
    if [ "$DRY_RUN" == "true" ]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} $1"
    else
        echo -e "${GREEN}[EXECUTING]${NC} $1"
        eval "$1" 2>/dev/null || true
    fi
}

# ===== IAM CLEANUP (Global - not region-specific) =====

# 0a. Deactivate and Delete IAM Access Keys
echo -e "\n${GREEN}>>> Deactivating and Deleting IAM Access Keys...${NC}"
users=$(aws iam list-users --query 'Users[].UserName' --output text)
for user in $users; do
    # Skip AWS managed service-linked accounts
    if [[ "$user" == *"service-linked"* ]]; then
        continue
    fi
    
    access_keys=$(aws iam list-access-keys --user-name $user --query 'AccessKeyMetadata[].AccessKeyId' --output text)
    for key in $access_keys; do
        # First deactivate the key
        run_cmd "aws iam update-access-key --user-name $user --access-key-id $key --status Inactive"
        # Then delete it
        run_cmd "aws iam delete-access-key --user-name $user --access-key-id $key"
    done
done

# 0b. Delete IAM Login Profiles (console password)
echo -e "\n${GREEN}>>> Deleting IAM Login Profiles...${NC}"
for user in $users; do
    if [[ "$user" == *"service-linked"* ]]; then
        continue
    fi
    run_cmd "aws iam delete-login-profile --user-name $user"
done

# 0c. Delete IAM MFA Devices
echo -e "\n${GREEN}>>> Deactivating IAM MFA Devices...${NC}"
for user in $users; do
    if [[ "$user" == *"service-linked"* ]]; then
        continue
    fi
    
    mfa_devices=$(aws iam list-mfa-devices --user-name $user --query 'MFADevices[].SerialNumber' --output text)
    for mfa in $mfa_devices; do
        run_cmd "aws iam deactivate-mfa-device --user-name $user --serial-number $mfa"
    done
done

# 0d. Detach Inline Policies from Users
echo -e "\n${GREEN}>>> Removing Inline Policies from Users...${NC}"
for user in $users; do
    if [[ "$user" == *"service-linked"* ]]; then
        continue
    fi
    
    inline_policies=$(aws iam list-user-policies --user-name $user --query 'PolicyNames' --output text)
    for policy in $inline_policies; do
        run_cmd "aws iam delete-user-policy --user-name $user --policy-name $policy"
    done
done

# 0e. Detach Managed Policies from Users
echo -e "\n${GREEN}>>> Detaching Managed Policies from Users...${NC}"
for user in $users; do
    if [[ "$user" == *"service-linked"* ]]; then
        continue
    fi
    
    attached_policies=$(aws iam list-attached-user-policies --user-name $user --query 'AttachedPolicies[].PolicyArn' --output text)
    for policy_arn in $attached_policies; do
        run_cmd "aws iam detach-user-policy --user-name $user --policy-arn $policy_arn"
    done
done

# 0f. Remove Users from Groups
echo -e "\n${GREEN}>>> Removing Users from Groups...${NC}"
for user in $users; do
    if [[ "$user" == *"service-linked"* ]]; then
        continue
    fi
    
    groups=$(aws iam list-groups-for-user --user-name $user --query 'Groups[].GroupName' --output text)
    for group in $groups; do
        run_cmd "aws iam remove-user-from-group --user-name $user --group-name $group"
    done
done

# 0g. Delete IAM Users
echo -e "\n${GREEN}>>> Deleting IAM Users...${NC}"
for user in $users; do
    if [[ "$user" == *"service-linked"* ]]; then
        continue
    fi
    run_cmd "aws iam delete-user --user-name $user"
done

# 0h. Delete IAM Groups
echo -e "\n${GREEN}>>> Deleting IAM Groups...${NC}"
groups=$(aws iam list-groups --query 'Groups[].GroupName' --output text)
for group in $groups; do
    # Remove inline policies from group
    group_policies=$(aws iam list-group-policies --group-name $group --query 'PolicyNames' --output text)
    for policy in $group_policies; do
        run_cmd "aws iam delete-group-policy --group-name $group --policy-name $policy"
    done
    
    # Detach managed policies from group
    attached_policies=$(aws iam list-attached-group-policies --group-name $group --query 'AttachedPolicies[].PolicyArn' --output text)
    for policy_arn in $attached_policies; do
        run_cmd "aws iam detach-group-policy --group-name $group --policy-arn $policy_arn"
    done
    
    # Delete the group
    run_cmd "aws iam delete-group --group-name $group"
done

# 0i. Detach Inline Policies from Roles
echo -e "\n${GREEN}>>> Removing Inline Policies from Roles...${NC}"
roles=$(aws iam list-roles --query 'Roles[].RoleName' --output text)
for role in $roles; do
    inline_policies=$(aws iam list-role-policies --role-name $role --query 'PolicyNames' --output text 2>/dev/null || echo "")
    for policy in $inline_policies; do
        run_cmd "aws iam delete-role-policy --role-name $role --policy-name $policy"
    done
done

# 0j. Detach Managed Policies from Roles
echo -e "\n${GREEN}>>> Detaching Managed Policies from Roles...${NC}"
for role in $roles; do
    attached_policies=$(aws iam list-attached-role-policies --role-name $role --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || echo "")
    for policy_arn in $attached_policies; do
        # Skip AWS managed policies
        if [[ "$policy_arn" != "arn:aws:iam::aws:policy/"* ]]; then
            run_cmd "aws iam detach-role-policy --role-name $role --policy-arn $policy_arn"
        fi
    done
done

# 0k. Delete Instance Profiles and Remove Roles
echo -e "\n${GREEN}>>> Deleting Instance Profiles...${NC}"
instance_profiles=$(aws iam list-instance-profiles --query 'InstanceProfiles[].InstanceProfileName' --output text)
for profile in $instance_profiles; do
    roles_in_profile=$(aws iam get-instance-profile --instance-profile-name $profile --query 'InstanceProfile.Roles[].RoleName' --output text)
    for role in $roles_in_profile; do
        run_cmd "aws iam remove-role-from-instance-profile --instance-profile-name $profile --role-name $role"
    done
    run_cmd "aws iam delete-instance-profile --instance-profile-name $profile"
done

# 0l. Delete Custom IAM Policies
echo -e "\n${GREEN}>>> Deleting Custom IAM Policies...${NC}"
policies=$(aws iam list-policies --scope Local --query 'Policies[].Arn' --output text)
for policy_arn in $policies; do
    # Delete all versions except default
    versions=$(aws iam list-policy-versions --policy-arn $policy_arn --query 'Versions[?!IsDefaultVersion].VersionId' --output text)
    for version in $versions; do
        run_cmd "aws iam delete-policy-version --policy-arn $policy_arn --version-id $version"
    done
    
    # Delete the policy itself
    run_cmd "aws iam delete-policy --policy-arn $policy_arn"
done

# 0m. Delete IAM Roles (user-created only)
echo -e "\n${GREEN}>>> Deleting IAM Roles...${NC}"
for role in $roles; do
    # Skip AWS service-linked roles
    if [[ "$role" == *"AWSServiceRoleFor"* ]] || [[ "$role" == *"aws-service-role"* ]]; then
        continue
    fi
    
    run_cmd "aws iam delete-role --role-name $role" 2>/dev/null || true
done

# ===== REGIONAL RESOURCE CLEANUP =====

# 1. EC2 Instances
echo -e "\n${GREEN}>>> Terminating EC2 Instances...${NC}"
instances=$(aws ec2 describe-instances --region $REGION --query 'Reservations[].Instances[?State.Name!=`terminated`].InstanceId' --output text)
for id in $instances; do
    run_cmd "aws ec2 modify-instance-attribute --region $REGION --instance-id $id --no-disable-api-termination"
    run_cmd "aws ec2 terminate-instances --region $REGION --instance-ids $id"
done

# 2. Auto Scaling Groups
echo -e "\n${GREEN}>>> Deleting Auto Scaling Groups...${NC}"
asgs=$(aws autoscaling describe-auto-scaling-groups --region $REGION --query 'AutoScalingGroups[].AutoScalingGroupName' --output text)
for asg in $asgs; do
    run_cmd "aws autoscaling update-auto-scaling-group --region $REGION --auto-scaling-group-name $asg --min-size 0 --desired-capacity 0"
    run_cmd "aws autoscaling delete-auto-scaling-group --region $REGION --auto-scaling-group-name $asg --force-delete"
done

# 3. Launch Configurations
echo -e "\n${GREEN}>>> Deleting Launch Configurations...${NC}"
lcs=$(aws autoscaling describe-launch-configurations --region $REGION --query 'LaunchConfigurations[].LaunchConfigurationName' --output text)
for lc in $lcs; do
    run_cmd "aws autoscaling delete-launch-configuration --region $REGION --launch-configuration-name $lc"
done

# 4. ELBs (Classic)
echo -e "\n${GREEN}>>> Deleting Classic Load Balancers...${NC}"
elbs=$(aws elb describe-load-balancers --region $REGION --query 'LoadBalancerDescriptions[].LoadBalancerName' --output text)
for elb in $elbs; do
    run_cmd "aws elb delete-load-balancer --region $REGION --load-balancer-name $elb"
done

# 5. ALBs/NLBs
echo -e "\n${GREEN}>>> Deleting Application/Network Load Balancers...${NC}"
lbs=$(aws elbv2 describe-load-balancers --region $REGION --query 'LoadBalancers[].LoadBalancerArn' --output text)
for lb in $lbs; do
    run_cmd "aws elbv2 delete-load-balancer --region $REGION --load-balancer-arn $lb"
done

# 6. Target Groups
echo -e "\n${GREEN}>>> Deleting Target Groups...${NC}"
tgs=$(aws elbv2 describe-target-groups --region $REGION --query 'TargetGroups[].TargetGroupArn' --output text)
for tg in $tgs; do
    run_cmd "aws elbv2 delete-target-group --region $REGION --target-group-arn $tg"
done

# 7. RDS Instances
echo -e "\n${GREEN}>>> Deleting RDS Instances...${NC}"
rdss=$(aws rds describe-db-instances --region $REGION --query 'DBInstances[].DBInstanceIdentifier' --output text)
for rds in $rdss; do
    run_cmd "aws rds modify-db-instance --region $REGION --db-instance-identifier $rds --deletion-protection --no-deletion-protection"
    run_cmd "aws rds delete-db-instance --region $REGION --db-instance-identifier $rds --skip-final-snapshot --delete-automated-backups"
done

# 8. RDS Clusters
echo -e "\n${GREEN}>>> Deleting RDS Clusters...${NC}"
clusters=$(aws rds describe-db-clusters --region $REGION --query 'DBClusters[].DBClusterIdentifier' --output text)
for cluster in $clusters; do
    run_cmd "aws rds delete-db-cluster --region $REGION --db-cluster-identifier $cluster --skip-final-snapshot"
done

# 9. ElastiCache Clusters
echo -e "\n${GREEN}>>> Deleting ElastiCache Clusters...${NC}"
caches=$(aws elasticache describe-cache-clusters --region $REGION --query 'CacheClusters[].CacheClusterId' --output text)
for cache in $caches; do
    run_cmd "aws elasticache delete-cache-cluster --region $REGION --cache-cluster-id $cache"
done

# 10. Lambda Functions
echo -e "\n${GREEN}>>> Deleting Lambda Functions...${NC}"
lambdas=$(aws lambda list-functions --region $REGION --query 'Functions[].FunctionName' --output text)
for fn in $lambdas; do
    run_cmd "aws lambda delete-function --region $REGION --function-name $fn"
done

# 11. API Gateways (REST)
echo -e "\n${GREEN}>>> Deleting API Gateway REST APIs...${NC}"
apis=$(aws apigateway get-rest-apis --region $REGION --query 'items[].id' --output text)
for api in $apis; do
    run_cmd "aws apigateway delete-rest-api --region $REGION --rest-api-id $api"
done

# 12. API Gateways (HTTP/WebSocket)
echo -e "\n${GREEN}>>> Deleting API Gateway V2 APIs...${NC}"
apisv2=$(aws apigatewayv2 get-apis --region $REGION --query 'Items[].ApiId' --output text)
for api in $apisv2; do
    run_cmd "aws apigatewayv2 delete-api --region $REGION --api-id $api"
done

# 13. ECS Clusters
echo -e "\n${GREEN}>>> Deleting ECS Clusters...${NC}"
ecs_clusters=$(aws ecs list-clusters --region $REGION --query 'clusterArns' --output text)
for cluster in $ecs_clusters; do
    services=$(aws ecs list-services --region $REGION --cluster $cluster --query 'serviceArns' --output text)
    for svc in $services; do
        run_cmd "aws ecs update-service --region $REGION --cluster $cluster --service $svc --desired-count 0"
        run_cmd "aws ecs delete-service --region $REGION --cluster $cluster --service $svc --force"
    done
    run_cmd "aws ecs delete-cluster --region $REGION --cluster $cluster"
done

# 14. ECR Repositories
echo -e "\n${GREEN}>>> Deleting ECR Repositories...${NC}"
repos=$(aws ecr describe-repositories --region $REGION --query 'repositories[].repositoryName' --output text)
for repo in $repos; do
    run_cmd "aws ecr delete-repository --region $REGION --repository-name $repo --force"
done

# 15. EKS Clusters
echo -e "\n${GREEN}>>> Deleting EKS Clusters...${NC}"
eks_clusters=$(aws eks list-clusters --region $REGION --query 'clusters' --output text)
for cluster in $eks_clusters; do
    nodegroups=$(aws eks list-nodegroups --region $REGION --cluster-name $cluster --query 'nodegroups' --output text)
    for ng in $nodegroups; do
        run_cmd "aws eks delete-nodegroup --region $REGION --cluster-name $cluster --nodegroup-name $ng"
    done
    run_cmd "aws eks delete-cluster --region $REGION --name $cluster"
done

# 16. SNS Topics
echo -e "\n${GREEN}>>> Deleting SNS Topics...${NC}"
topics=$(aws sns list-topics --region $REGION --query 'Topics[].TopicArn' --output text)
for topic in $topics; do
    run_cmd "aws sns delete-topic --region $REGION --topic-arn $topic"
done

# 17. SQS Queues
echo -e "\n${GREEN}>>> Deleting SQS Queues...${NC}"
queues=$(aws sqs list-queues --region $REGION --query 'QueueUrls' --output text)
for queue in $queues; do
    run_cmd "aws sqs delete-queue --region $REGION --queue-url $queue"
done

# 18. CloudWatch Log Groups
echo -e "\n${GREEN}>>> Deleting CloudWatch Log Groups...${NC}"
logs=$(aws logs describe-log-groups --region $REGION --query 'logGroups[].logGroupName' --output text)
for log in $logs; do
    run_cmd "aws logs delete-log-group --region $REGION --log-group-name $log"
done

# 18a. CloudWatch Alarms
echo -e "\n${GREEN}>>> Deleting CloudWatch Alarms...${NC}"
alarms=$(aws cloudwatch describe-alarms --region $REGION --query 'MetricAlarms[].AlarmName' --output text)
for alarm in $alarms; do
    run_cmd "aws cloudwatch delete-alarms --region $REGION --alarm-names $alarm"
done

# 18b. CloudWatch Composite Alarms
echo -e "\n${GREEN}>>> Deleting CloudWatch Composite Alarms...${NC}"
composite_alarms=$(aws cloudwatch describe-alarms --region $REGION --alarm-types CompositeAlarm --query 'CompositeAlarms[].AlarmName' --output text)
for alarm in $composite_alarms; do
    run_cmd "aws cloudwatch delete-alarms --region $REGION --alarm-names $alarm"
done

# 18c. CloudWatch Dashboards
echo -e "\n${GREEN}>>> Deleting CloudWatch Dashboards...${NC}"
dashboards=$(aws cloudwatch list-dashboards --region $REGION --query 'DashboardEntries[].DashboardName' --output text)
for dash in $dashboards; do
    run_cmd "aws cloudwatch delete-dashboards --region $REGION --dashboard-names $dash"
done

# 18d. CloudWatch Metric Streams
echo -e "\n${GREEN}>>> Deleting CloudWatch Metric Streams...${NC}"
streams=$(aws cloudwatch list-metric-streams --region $REGION --query 'Entries[].Name' --output text)
for stream in $streams; do
    run_cmd "aws cloudwatch delete-metric-stream --region $REGION --name $stream"
done

# 18e. CloudWatch Insights Rules
echo -e "\n${GREEN}>>> Deleting CloudWatch Insights Rules...${NC}"
rules=$(aws cloudwatch describe-insight-rules --region $REGION --query 'InsightRules[].Name' --output text)
for rule in $rules; do
    run_cmd "aws cloudwatch delete-insight-rules --region $REGION --rule-names $rule"
done

# 18f. EventBridge Rules
echo -e "\n${GREEN}>>> Deleting EventBridge Rules...${NC}"
buses=$(aws events list-event-buses --region $REGION --query 'EventBuses[].Name' --output text)
for bus in $buses; do
    rules=$(aws events list-rules --region $REGION --event-bus-name $bus --query 'Rules[].Name' --output text)
    for rule in $rules; do
        targets=$(aws events list-targets-by-rule --region $REGION --event-bus-name $bus --rule $rule --query 'Targets[].Id' --output text)
        if [ -n "$targets" ]; then
            run_cmd "aws events remove-targets --region $REGION --event-bus-name $bus --rule $rule --ids $targets"
        fi
        run_cmd "aws events delete-rule --region $REGION --event-bus-name $bus --name $rule"
    done
    if [ "$bus" != "default" ]; then
        run_cmd "aws events delete-event-bus --region $REGION --name $bus"
    fi
done

# 19. Secrets Manager Secrets
echo -e "\n${GREEN}>>> Deleting Secrets Manager Secrets...${NC}"
secrets=$(aws secretsmanager list-secrets --region $REGION --query 'SecretList[].ARN' --output text)
for secret in $secrets; do
    run_cmd "aws secretsmanager delete-secret --region $REGION --secret-id $secret --force-delete-without-recovery"
done

# 20. KMS Keys (schedule deletion)
echo -e "\n${GREEN}>>> Scheduling KMS Key Deletion...${NC}"
keys=$(aws kms list-keys --region $REGION --query 'Keys[].KeyId' --output text)
for key in $keys; do
    key_info=$(aws kms describe-key --region $REGION --key-id $key --query 'KeyMetadata.KeyManager' --output text)
    if [ "$key_info" == "CUSTOMER" ]; then
        run_cmd "aws kms schedule-key-deletion --region $REGION --key-id $key --pending-window-in-days 7"
    fi
done

# 21. EBS Volumes
echo -e "\n${GREEN}>>> Deleting EBS Volumes...${NC}"
volumes=$(aws ec2 describe-volumes --region $REGION --query 'Volumes[?State==`available`].VolumeId' --output text)
for vol in $volumes; do
    run_cmd "aws ec2 delete-volume --region $REGION --volume-id $vol"
done

# 22. EBS Snapshots
echo -e "\n${GREEN}>>> Deleting EBS Snapshots...${NC}"
account_id=$(aws sts get-caller-identity --query 'Account' --output text)
snapshots=$(aws ec2 describe-snapshots --region $REGION --owner-ids $account_id --query 'Snapshots[].SnapshotId' --output text)
for snap in $snapshots; do
    run_cmd "aws ec2 delete-snapshot --region $REGION --snapshot-id $snap"
done

# 23. AMIs
echo -e "\n${GREEN}>>> Deregistering AMIs...${NC}"
amis=$(aws ec2 describe-images --region $REGION --owners self --query 'Images[].ImageId' --output text)
for ami in $amis; do
    run_cmd "aws ec2 deregister-image --region $REGION --image-id $ami"
done

# 24. NAT Gateways
echo -e "\n${GREEN}>>> Deleting NAT Gateways...${NC}"
nats=$(aws ec2 describe-nat-gateways --region $REGION --filter "Name=state,Values=available" --query 'NatGateways[].NatGatewayId' --output text)
for nat in $nats; do
    run_cmd "aws ec2 delete-nat-gateway --region $REGION --nat-gateway-id $nat"
done

# 25. Elastic IPs
echo -e "\n${GREEN}>>> Releasing Elastic IPs...${NC}"
eips=$(aws ec2 describe-addresses --region $REGION --query 'Addresses[].AllocationId' --output text)
for eip in $eips; do
    run_cmd "aws ec2 release-address --region $REGION --allocation-id $eip"
done

# 26. Internet Gateways
echo -e "\n${GREEN}>>> Deleting Internet Gateways...${NC}"
igws=$(aws ec2 describe-internet-gateways --region $REGION --query 'InternetGateways[].InternetGatewayId' --output text)
for igw in $igws; do
    vpc=$(aws ec2 describe-internet-gateways --region $REGION --internet-gateway-ids $igw --query 'InternetGateways[].Attachments[].VpcId' --output text)
    if [ -n "$vpc" ]; then
        run_cmd "aws ec2 detach-internet-gateway --region $REGION --internet-gateway-id $igw --vpc-id $vpc"
    fi
    run_cmd "aws ec2 delete-internet-gateway --region $REGION --internet-gateway-id $igw"
done

# 27. VPC Endpoints
echo -e "\n${GREEN}>>> Deleting VPC Endpoints...${NC}"
endpoints=$(aws ec2 describe-vpc-endpoints --region $REGION --query 'VpcEndpoints[].VpcEndpointId' --output text)
for ep in $endpoints; do
    run_cmd "aws ec2 delete-vpc-endpoints --region $REGION --vpc-endpoint-ids $ep"
done

# 28. Remove Security Group Rules (to break circular dependencies)
echo -e "\n${GREEN}>>> Removing Security Group Rules...${NC}"
sgs=$(aws ec2 describe-security-groups --region $REGION --query 'SecurityGroups[].GroupId' --output text)
for sg in $sgs; do
    # Remove ingress rules
    rules=$(aws ec2 describe-security-groups --region $REGION --group-ids $sg --query 'SecurityGroups[].IpPermissions' --output json)
    if [ "$rules" != "[[]]" ] && [ "$rules" != "[]" ]; then
        run_cmd "aws ec2 revoke-security-group-ingress --region $REGION --group-id $sg --ip-permissions '$rules' 2>/dev/null"
    fi
    # Remove egress rules
    egress=$(aws ec2 describe-security-groups --region $REGION --group-ids $sg --query 'SecurityGroups[].IpPermissionsEgress' --output json)
    if [ "$egress" != "[[]]" ] && [ "$egress" != "[]" ]; then
        run_cmd "aws ec2 revoke-security-group-egress --region $REGION --group-id $sg --ip-permissions '$egress' 2>/dev/null"
    fi
done

# 29. Delete Security Groups (ALL including default where possible)
echo -e "\n${GREEN}>>> Deleting Security Groups...${NC}"
sgs=$(aws ec2 describe-security-groups --region $REGION --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text)
for sg in $sgs; do
    run_cmd "aws ec2 delete-security-group --region $REGION --group-id $sg"
done

# 30. Delete Network ACLs (non-default)
echo -e "\n${GREEN}>>> Deleting Network ACLs...${NC}"
nacls=$(aws ec2 describe-network-acls --region $REGION --query 'NetworkAcls[?IsDefault==`false`].NetworkAclId' --output text)
for nacl in $nacls; do
    run_cmd "aws ec2 delete-network-acl --region $REGION --network-acl-id $nacl"
done

# 31. Delete Network Interfaces
echo -e "\n${GREEN}>>> Deleting Network Interfaces...${NC}"
enis=$(aws ec2 describe-network-interfaces --region $REGION --query 'NetworkInterfaces[].NetworkInterfaceId' --output text)
for eni in $enis; do
    attachment=$(aws ec2 describe-network-interfaces --region $REGION --network-interface-ids $eni --query 'NetworkInterfaces[].Attachment.AttachmentId' --output text)
    if [ -n "$attachment" ] && [ "$attachment" != "None" ]; then
        run_cmd "aws ec2 detach-network-interface --region $REGION --attachment-id $attachment --force"
        sleep 2
    fi
    run_cmd "aws ec2 delete-network-interface --region $REGION --network-interface-id $eni"
done

# 32. Delete Subnets (ALL)
echo -e "\n${GREEN}>>> Deleting Subnets...${NC}"
subnets=$(aws ec2 describe-subnets --region $REGION --query 'Subnets[].SubnetId' --output text)
for subnet in $subnets; do
    run_cmd "aws ec2 delete-subnet --region $REGION --subnet-id $subnet"
done

# 33. Delete Route Tables (non-main)
echo -e "\n${GREEN}>>> Deleting Route Tables...${NC}"
rts=$(aws ec2 describe-route-tables --region $REGION --query 'RouteTables[].RouteTableId' --output text)
for rt in $rts; do
    # Disassociate first
    assocs=$(aws ec2 describe-route-tables --region $REGION --route-table-ids $rt --query 'RouteTables[].Associations[?!Main].RouteTableAssociationId' --output text)
    for assoc in $assocs; do
        run_cmd "aws ec2 disassociate-route-table --region $REGION --association-id $assoc"
    done
    # Check if main route table
    is_main=$(aws ec2 describe-route-tables --region $REGION --route-table-ids $rt --query 'RouteTables[].Associations[?Main==`true`]' --output text)
    if [ -z "$is_main" ]; then
        run_cmd "aws ec2 delete-route-table --region $REGION --route-table-id $rt"
    fi
done

# 34. Delete VPCs (ALL including default)
echo -e "\n${GREEN}>>> Deleting VPCs (including default)...${NC}"
vpcs=$(aws ec2 describe-vpcs --region $REGION --query 'Vpcs[].VpcId' --output text)
for vpc in $vpcs; do
    run_cmd "aws ec2 delete-vpc --region $REGION --vpc-id $vpc"
done

# 35. S3 Buckets in region
echo -e "\n${GREEN}>>> Deleting S3 Buckets...${NC}"
buckets=$(aws s3api list-buckets --query 'Buckets[].Name' --output text)
for bucket in $buckets; do
    bucket_region=$(aws s3api get-bucket-location --bucket $bucket --query 'LocationConstraint' --output text 2>/dev/null || echo "error")
    [ "$bucket_region" == "null" ] && bucket_region="us-east-1"
    if [ "$bucket_region" == "$REGION" ]; then
        run_cmd "aws s3 rb s3://$bucket --force"
    fi
done

# 36. DynamoDB Tables
echo -e "\n${GREEN}>>> Deleting DynamoDB Tables...${NC}"
tables=$(aws dynamodb list-tables --region $REGION --query 'TableNames' --output text)
for table in $tables; do
    run_cmd "aws dynamodb delete-table --region $REGION --table-name $table"
done

# 37. Kinesis Streams
echo -e "\n${GREEN}>>> Deleting Kinesis Streams...${NC}"
streams=$(aws kinesis list-streams --region $REGION --query 'StreamNames' --output text)
for stream in $streams; do
    run_cmd "aws kinesis delete-stream --region $REGION --stream-name $stream --enforce-consumer-deletion"
done

# 38. CloudFormation Stacks
echo -e "\n${GREEN}>>> Deleting CloudFormation Stacks...${NC}"
stacks=$(aws cloudformation list-stacks --region $REGION --query 'StackSummaries[?StackStatus!=`DELETE_COMPLETE`].StackName' --output text)
for stack in $stacks; do
    run_cmd "aws cloudformation delete-stack --region $REGION --stack-name $stack"
done

# 39. Glue Databases and Tables
echo -e "\n${GREEN}>>> Deleting AWS Glue Databases...${NC}"
databases=$(aws glue get-databases --region $REGION --query 'DatabaseList[].Name' --output text 2>/dev/null || echo "")
for db in $databases; do
    # Delete tables in database first
    tables=$(aws glue get-tables --region $REGION --database-name $db --query 'TableList[].Name' --output text 2>/dev/null || echo "")
    for table in $tables; do
        run_cmd "aws glue delete-table --region $REGION --database-name $db --name $table"
    done
    # Delete database
    run_cmd "aws glue delete-database --region $REGION --name $db"
done

# 40. SageMaker Resources
echo -e "\n${GREEN}>>> Deleting SageMaker Endpoints and Models...${NC}"
endpoints=$(aws sagemaker list-endpoints --region $REGION --query 'Endpoints[].EndpointName' --output text 2>/dev/null || echo "")
for endpoint in $endpoints; do
    run_cmd "aws sagemaker delete-endpoint --region $REGION --endpoint-name $endpoint"
done

models=$(aws sagemaker list-models --region $REGION --query 'Models[].ModelName' --output text 2>/dev/null || echo "")
for model in $models; do
    run_cmd "aws sagemaker delete-model --region $REGION --model-name $model"
done

# 41. Batch Job Queues and Compute Environments
echo -e "\n${GREEN}>>> Deleting AWS Batch Resources...${NC}"
queues=$(aws batch describe-job-queues --region $REGION --query 'jobQueues[].jobQueueName' --output text 2>/dev/null || echo "")
for queue in $queues; do
    run_cmd "aws batch update-job-queue --region $REGION --job-queue $queue --state DISABLED"
    run_cmd "aws batch delete-job-queue --region $REGION --job-queue $queue"
done

compute_envs=$(aws batch describe-compute-environments --region $REGION --query 'computeEnvironments[].computeEnvironmentName' --output text 2>/dev/null || echo "")
for env in $compute_envs; do
    run_cmd "aws batch update-compute-environment --region $REGION --compute-environment $env --state DISABLED"
    run_cmd "aws batch delete-compute-environment --region $REGION --compute-environment $env"
done

# 42. Step Functions State Machines
echo -e "\n${GREEN}>>> Deleting Step Functions State Machines...${NC}"
state_machines=$(aws stepfunctions list-state-machines --region $REGION --query 'stateMachines[].stateMachineArn' --output text 2>/dev/null || echo "")
for sm in $state_machines; do
    run_cmd "aws stepfunctions delete-state-machine --region $REGION --state-machine-arn $sm"
done

# 43. Data Pipeline Objects
echo -e "\n${GREEN}>>> Deleting Data Pipeline Objects...${NC}"
pipelines=$(aws datapipeline list-pipelines --region $REGION --query 'pipelineIdList[].id' --output text 2>/dev/null || echo "")
for pipeline in $pipelines; do
    run_cmd "aws datapipeline delete-pipeline --region $REGION --pipeline-id $pipeline"
done

# 44. ElasticSearch Domains
echo -e "\n${GREEN}>>> Deleting Elasticsearch Domains...${NC}"
domains=$(aws es list-domain-names --region $REGION --query 'DomainNames[].DomainName' --output text 2>/dev/null || echo "")
for domain in $domains; do
    run_cmd "aws es delete-elasticsearch-domain --region $REGION --domain-name $domain"
done

# 45. OpenSearch Domains
echo -e "\n${GREEN}>>> Deleting OpenSearch Domains...${NC}"
os_domains=$(aws opensearch list-domain-names --region $REGION --query 'DomainNames[].DomainName' --output text 2>/dev/null || echo "")
for domain in $os_domains; do
    run_cmd "aws opensearch delete-domain --region $REGION --domain-name $domain"
done

# 46. DocumentDB Clusters
echo -e "\n${GREEN}>>> Deleting DocumentDB Clusters...${NC}"
doc_clusters=$(aws docdb describe-db-clusters --region $REGION --query 'DBClusters[].DBClusterIdentifier' --output text 2>/dev/null || echo "")
for cluster in $doc_clusters; do
    run_cmd "aws docdb delete-db-cluster --region $REGION --db-cluster-identifier $cluster --skip-final-snapshot"
done

# 47. Redshift Clusters
echo -e "\n${GREEN}>>> Deleting Redshift Clusters...${NC}"
rs_clusters=$(aws redshift describe-clusters --region $REGION --query 'Clusters[].ClusterIdentifier' --output text 2>/dev/null || echo "")
for cluster in $rs_clusters; do
    run_cmd "aws redshift delete-cluster --region $REGION --cluster-identifier $cluster --skip-final-cluster-snapshot"
done

# 48. AppSync GraphQL APIs
echo -e "\n${GREEN}>>> Deleting AppSync GraphQL APIs...${NC}"
appsync_apis=$(aws appsync list-graphql-apis --region $REGION --query 'graphqlApis[].apiId' --output text 2>/dev/null || echo "")
for api in $appsync_apis; do
    run_cmd "aws appsync delete-graphql-api --region $REGION --api-id $api"
done

# 49. CodePipeline Pipelines
echo -e "\n${GREEN}>>> Deleting CodePipeline Pipelines...${NC}"
pipelines=$(aws codepipeline list-pipelines --region $REGION --query 'pipelines[].name' --output text 2>/dev/null || echo "")
for pipeline in $pipelines; do
    run_cmd "aws codepipeline delete-pipeline --region $REGION --name $pipeline"
done

# 50. CodeBuild Projects
echo -e "\n${GREEN}>>> Deleting CodeBuild Projects...${NC}"
projects=$(aws codebuild list-projects --region $REGION --query 'projects' --output text 2>/dev/null || echo "")
for project in $projects; do
    run_cmd "aws codebuild delete-project --region $REGION --name $project"
done

echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}  Cleanup Complete!${NC}"
echo -e "${GREEN}  Region: ${REGION}${NC}"
if [ "$DRY_RUN" == "true" ]; then
    echo -e "${YELLOW}  This was a DRY RUN - no resources were deleted${NC}"
    echo -e "${YELLOW}  Run with: $0 $REGION false${NC}"
fi
echo -e "${GREEN}============================================${NC}"
