package controllers

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"log"
)

type Api struct {
	conn *ec2.EC2
}

type AwsAccount struct {
	AccountId  string
	RoleName   string
	ExternalId string
}

func (a *AwsAccount) CreateARN() string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", a.AccountId, a.RoleName)
}

func New(awsAccount AwsAccount, region string) (api Api, err error) {
	sess, err := session.NewSession()
	if err != nil {
		return api, err
	}
	conf := CreateConfig(awsAccount, region, sess)
	return Api{conn: ec2.New(sess, &conf)}, nil
}

func CreateConfig(awsAccount AwsAccount, region string, sess *session.Session) (conf aws.Config) {
	conf = aws.Config{Region: aws.String(region)}

	// if ARN flag is passed in, we need to be able ot assume role here
	var creds *credentials.Credentials

	if awsAccount.ExternalId != "" {
		// If externalID flag is passed, we need to include it in credentials struct
		creds = stscreds.NewCredentials(sess, awsAccount.CreateARN(), func(p *stscreds.AssumeRoleProvider) {
			p.ExternalID = &awsAccount.ExternalId
		})
	} else {
		creds = stscreds.NewCredentials(sess, awsAccount.CreateARN(), func(p *stscreds.AssumeRoleProvider) {})
	}

	conf.Credentials = creds

	return
}

type CreateInstanceParameter struct {
	Ami    string
	Family string
}

type InstanceID *string

func (a *Api) CreateInstance(parameter CreateInstanceParameter, tags Tags) (InstanceID, error) {
	runResult, err := a.conn.RunInstances(&ec2.RunInstancesInput{
		ImageId:      aws.String(parameter.Ami),
		InstanceType: aws.String(parameter.Family),
		MinCount:     aws.Int64(1),
		MaxCount:     aws.Int64(1),
	})

	a.conn.CreateTags(&ec2.CreateTagsInput{
		Tags:      tags.toEc2Tags(),
		Resources: []*string{runResult.Instances[0].InstanceId},
	})

	if err != nil {
		log.Println("could not create instance", err)
		return nil, err
	}

	return runResult.Instances[0].InstanceId, nil
}

func (a *Api) GetInstancesByTags(tags []Tag) ([]*AwsInstance, error) {
	var filters []*ec2.Filter

	for _, tag := range tags {
		filters = append(filters, &ec2.Filter{
			Name:   aws.String("tag:" + tag.Key),
			Values: []*string{aws.String(tag.Value)},
		})
	}

	input := &ec2.DescribeInstancesInput{Filters: filters}
	result, err := a.conn.DescribeInstances(input)
	if err != nil {
		return nil, err
	}

	return a.convertAwsInstances(result.Reservations), nil
}

func (a *Api) GetInstanceById(instanceId string) (*AwsInstance, error) {
	if len(instanceId) == 0 {
		return nil, fmt.Errorf("instance id must contain id")
	}

	if instanceId[0:2] != "i-" {
		return nil, fmt.Errorf("instance id must starts with 'i-'. input: %s", instanceId)
	}

	input := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(instanceId)},
	}
	result, err := a.conn.DescribeInstances(input)
	if err != nil {
		return nil, err
	}

	instances := a.convertAwsInstances(result.Reservations)

	if len(instances) == 0 {
		return &AwsInstance{}, fmt.Errorf("instance id %s is not found", instanceId)
	} else {
		return instances[0], nil
	}
}

type Tag struct {
	Key   string
	Value string
}

type AwsInstance struct {
	InstanceID       string
	Name             string
	PrivateAddress   string
	PublicAddress    string
	Tags             Tags
	SecurityGroupIds []string
	Status           string
}

type InstanceWithConnection struct {
	instance *AwsInstance
	conn     *ec2.EC2
}

func NewInstanceWithConnection(instance *AwsInstance, conn *ec2.EC2) *InstanceWithConnection {
	return &InstanceWithConnection{
		instance: instance,
		conn:     conn,
	}
}

func (a *InstanceWithConnection) Stop() error {
	req := ec2.StopInstancesInput{
		InstanceIds: []*string{aws.String(a.instance.InstanceID)},
	}

	if _, err := a.conn.StopInstances(&req); err != nil {
		return err
	}

	return nil
}
func (a *InstanceWithConnection) Start() error {
	req := ec2.StartInstancesInput{
		InstanceIds: []*string{aws.String(a.instance.InstanceID)},
	}

	if _, err := a.conn.StartInstances(&req); err != nil {
		return err
	}

	return nil
}

func createInput(instanceId string) *ec2.DescribeTagsInput {
	return &ec2.DescribeTagsInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("resource-id"),
				Values: []*string{
					aws.String(instanceId),
				},
			},
		},
	}
}

func (a *Api) convertAwsInstances(reservations []*ec2.Reservation) []*AwsInstance {
	var instances []*AwsInstance

	for _, res := range reservations {
		for _, instance := range res.Instances {
			ec2Instance := AwsInstance{InstanceID: *instance.InstanceId}

			if instance.PrivateIpAddress != nil {
				ec2Instance.PrivateAddress = *instance.PrivateIpAddress
			}
			if instance.PublicIpAddress != nil {
				ec2Instance.PublicAddress = *instance.PublicIpAddress
			}

			ec2Instance.Status = aws.StringValue(instance.State.Name)
			ec2Instance.SecurityGroupIds = a.convertSecurityGroup(instance.SecurityGroups)

			awsTags, err := a.conn.DescribeTags(createInput(ec2Instance.InstanceID))
			if err != nil {
				log.Println(err)
			}

			tags := a.convertAwsTagsToTags(awsTags)
			ec2Instance.Name = tags.FindValueOrElse("Name", "")
			ec2Instance.Tags = tags

			instances = append(instances, &ec2Instance)
		}
	}

	return instances
}

func (a *Api) convertAwsTagsToTags(awsTags *ec2.DescribeTagsOutput) Tags {
	var tags Tags
	for _, tag := range awsTags.Tags {
		if tag.Key != nil {
			tags.append(Tag{Key: aws.StringValue(tag.Key), Value: aws.StringValue(tag.Value)})
		}
	}
	return tags
}

func (a *Api) convertSecurityGroup(securityGroups []*ec2.GroupIdentifier) []string {
	var result = []string{}
	for _, sg := range securityGroups {
		result = append(result, aws.StringValue(sg.GroupId))
	}
	return result
}

type Tags struct {
	Tags []Tag
}

func (t *Tags) append(tag Tag) {
	t.Tags = append(t.Tags, tag)
}

func (t *Tags) FindValue(tagName string) (string, bool) {
	for _, t := range t.Tags {
		if t.Key == tagName {
			return t.Value, true
		}
	}
	return "", false
}

func (t *Tags) FindValueOrElse(tagName string, defaultValue string) string {
	for _, t := range t.Tags {
		if t.Key == tagName {
			return t.Value
		}
	}
	return defaultValue
}

func (t *Tags) toArray() []Tag {
	return t.Tags
}
func (t *Tags) toEc2Tags() []*ec2.Tag {
	var ec2tags []*ec2.Tag

	for _, t := range t.Tags {
		ec2tags = append(ec2tags, &ec2.Tag{
			Key:   aws.String(t.Key),
			Value: aws.String(t.Value),
		})
	}

	return ec2tags
}
