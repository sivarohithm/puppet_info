import boto3
import json
iam = boto3.resource('iam')

denyPolicyArn = 'arn:aws:iam::*:policy/assume-role-test'
iamAdminGroup = 'iamadmins'
userName = 'rohith'

def lambda_handler( event, context ):
	print("Event data:")
	print(event)
	print (event['eventName'])
	print (event["eventName"])
	event_name = event["eventName"]
	if 'CreateImage'in event_name :
		revokeIamAccess(userName)
		return
	else:
		IamAccess()
		return
		
def revokeIamAccess(userName):

	policy = iam.Policy(denyPolicyArn)
	try:
		print("Attaching revoke policy '{}' to user '{}'.".format( denyPolicyArn, userName ))
		policy.attach_user( UserName=userName )
	except Exception as e:
		print("{}".format(e) )

def IamAccess():
	print("Not Attaching" )
