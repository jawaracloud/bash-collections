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

# 32. S3 Buckets in region
echo -e "\n${GREEN}>>> Deleting S3 Buckets...${NC}"
buckets=$(aws s3api list-buckets --query 'Buckets[].Name' --output text)
for bucket in $buckets; do
    bucket_region=$(aws s3api get-bucket-location --bucket $bucket --query 'LocationConstraint' --output text 2>/dev/null || echo "error")
    [ "$bucket_region" == "null" ] && bucket_region="us-east-1"
    if [ "$bucket_region" == "$REGION" ]; then
        run_cmd "aws s3 rb s3://$bucket --force"
    fi
done

# 33. DynamoDB Tables
echo -e "\n${GREEN}>>> Deleting DynamoDB Tables...${NC}"
tables=$(aws dynamodb list-tables --region $REGION --query 'TableNames' --output text)
for table in $tables; do
    run_cmd "aws dynamodb delete-table --region $REGION --table-name $table"
done

# 34. Kinesis Streams
echo -e "\n${GREEN}>>> Deleting Kinesis Streams...${NC}"
streams=$(aws kinesis list-streams --region $REGION --query 'StreamNames' --output text)
for stream in $streams; do
    run_cmd "aws kinesis delete-stream --region $REGION --stream-name $stream --enforce-consumer-deletion"
done

# 35. CloudFormation Stacks
echo -e "\n${GREEN}>>> Deleting CloudFormation Stacks...${NC}"
stacks=$(aws cloudformation list-stacks --region $REGION --query 'StackSummaries[?StackStatus!=`DELETE_COMPLETE`].StackName' --output text)
for stack in $stacks; do
    run_cmd "aws cloudformation delete-stack --region $REGION --stack-name $stack"
done

echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}  Cleanup Complete!${NC}"
echo -e "${GREEN}  Region: ${REGION}${NC}"
if [ "$DRY_RUN" == "true" ]; then
    echo -e "${YELLOW}  This was a DRY RUN - no resources were deleted${NC}"
    echo -e "${YELLOW}  Run with: $0 $REGION false${NC}"
fi
echo -e "${GREEN}============================================${NC}"
