import re
import os
import boto3
import importlib
import json
import sys
import traceback
from botocore.exceptions import ClientError

MININAL_TAG_LENGTH = 2
MININAL_ACTION_LENGTH = 1
permissions_link = 'https://github.com/dome9/cloud-bots/blob/master/template.yml'
relaunch_stack = 'https://github.com/dome9/cloud-bots#update-cloudbots'
account_mode = os.getenv('ACCOUNT_MODE', '')
cross_account_role_name = os.getenv('CROSS_ACCOUNT_ROLE_NAME', '')


def get_data_from_message(message):
    data = {}
    if 'rule' in message:
        data['rule_name'] = message['rule'].get('name')
        if 'complianceTags' in message['rule']:
            # All of the remediation values are coming in on the compliance tags and they're pipe delimited
            data['compliance_tags'] = message['rule']['complianceTags'].split('|')
    if 'status' in message:
        data['status'] = message['status']
    entity = message.get('entity')
    if entity:
        data['entity_id'] = entity.get('id')
        data['entity_name'] = entity.get('name')
        data['region'] = entity.get('region')
    # Some events come through with 'null' as the region. If so, default to us-east-1
    if not data.get('region'):
        data['region'] = 'us-east-1'
    else:
        data['region'] = data['region'].replace('_', '-')
    if 'remediationActions' in message:
        data['remediationActions'] = message['remediationActions']
    return data


def get_bots_from_finding(compliance_tags, remediation_actions):
    bots = []
    policy = None
    # Check if any of the tags have AUTO: in them. If there's nothing to do at all, skip it.
    if compliance_tags is not None:
        auto_pattern = re.compile('AUTO:')
        for tag in compliance_tags:
            tag = tag.strip()  # Sometimes the tags come through with trailing or leading spaces.
            # Check the tag to see if we have AUTO: in it
            if auto_pattern.match(tag):
                tag_pattern = tuple(tag.split(' '))
                # The format is AUTO: bot_name param1 param2
                if len(tag_pattern) < MININAL_TAG_LENGTH:
                    continue
                tag, bot, *params = tag_pattern
                bots.append([bot, params])

    if remediation_actions is not None:
        for action in remediation_actions:
            try:
                remAction = json.loads(action)
                if 'SuggestedRole' in remAction:
                    policy = 'SuggestedPolicy:%s' % remAction['SuggestedRole']
            except ValueError as e:
                action_pattern = tuple(action.split(' '))
                # The format is bot_name param1 param2
                if len(action_pattern) < MININAL_ACTION_LENGTH:
                    continue
                bot, *params = action_pattern
                if policy:
                    params.append(policy)
                bots.append((bot, params))
    return bots


def handle_event(message, output_message):
    post_to_sns = True
    message_data = get_data_from_message(message)
    role_arn = None

    # evaluate the event and tags and decide is there's something to do with them.
    if message_data.get('status') == 'Passed':
        print(f'''{__file__} - Rule: {message_data.get('rule_name')} passed''')
        return False

    compliance_tags = message_data.get('compliance_tags')
    remediation_actions = message_data.get('remediationActions')
    output_message['Rules violations found'] = []
    bots = get_bots_from_finding(compliance_tags, remediation_actions)
    if not bots or not len(bots):
        print(f'''{__file__} - Rule: {message_data.get('rule_name')} Doesnt have any bots to run. Skipping.''')
        return False

    for bot_to_run in bots:
        bot_msg = ''
        bot_data = {}
        bot_data['Rule'] = message_data.get('rule_name')
        bot_data['ID'] = message_data.get('entity_id')
        bot_data['Name'] = message_data.get('entity_name')
        bot, params = bot_to_run
        bot_data['Remediation'] = bot
        print(f'''{__file__} - Bot name to execute: {bot}''')
        try:
            bot_module = importlib.import_module(''.join(['bots.', bot]), package=None)
        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            bot_msg = f'{__file__} - Error in function {bot}. function didnt execute. Error: {e}. For more details please see the CloudWatch logs. \n'
            bot_data['Execution status'] = 'failed'
            print(
                f'{__file__} Details: {" ".join(traceback.format_exception(exception_type, exception_object, exception_traceback))} \n')
            bot_data['Bot message'] = bot_msg
            output_message['Rules violations found'].append(bot_data.copy())
            continue

        # Get the session info here. No point in waisting cycles running it up top if we aren't going to run an bot anyways:
        try:  # get the accountID
            sts = boto3.client('sts')
            lambda_account_id = sts.get_caller_identity()['Account']

        except ClientError as e:
            print(f'{__file__} Unexpected STS error - {e}')
            # return False

        event_account_id = output_message['Account id']
        # Account mode will be set in the lambda variables. We'll default to single mode
        if lambda_account_id != event_account_id:  # The remediation needs to be done outside of this account
            if account_mode == 'multi':  # multi or single account mode?
                # If it's not the same account, try to assume role to the new one
                role_arn = ''.join(['arn:aws:iam::', event_account_id, ':role/'])
                # This allows users to set their own role name if they have a different naming convention they have to follow
                role_arn = ''.join([role_arn, cross_account_role_name]) if cross_account_role_name else ''.join(
                    [role_arn, 'Dome9CloudBots'])
                bot_data[
                    'Compliance failure was found for an account outside of the one the function is running in. Trying to assume_role to target account'] = event_account_id

                try:
                    credentials_for_event = globals()['all_session_credentials'][event_account_id]

                except (NameError, KeyError):
                    # If we can't find the credentials, try to generate new ones
                    global all_session_credentials
                    all_session_credentials = {}
                    # create an STS client object that represents a live connection to the STS service
                    sts_client = boto3.client('sts')

                    # Call the assume_role method of the STSConnection object and pass the role ARN and a role session name.
                    try:
                        assumedRoleObject = sts_client.assume_role(
                            RoleArn=role_arn,
                            RoleSessionName='CloudBotsAutoRemedation'
                        )
                        # From the response that contains the assumed role, get the temporary credentials that can be used to make subsequent API calls
                        all_session_credentials[event_account_id] = assumedRoleObject['Credentials']
                        credentials_for_event = all_session_credentials[event_account_id]

                    except ClientError as e:
                        error = e.response['Error']['Code']
                        bot_data['Execution status'] = 'failed'
                        print(f'{__file__} - Error - {e}')
                        if error == 'AccessDenied':
                            bot_data[
                                'Access Denied'] = 'Tried and failed to assume a role in the target account. Please verify that the cross account role is createad.'
                        else:
                            bot_data['Unexpected error'] = e
                        continue

                boto_session = boto3.Session(
                    region_name=message_data.get('region'),
                    aws_access_key_id=credentials_for_event['AccessKeyId'],
                    aws_secret_access_key=credentials_for_event['SecretAccessKey'],
                    aws_session_token=credentials_for_event['SessionToken']
                )

            else:
                # In single account mode, we don't want to try to run bots outside of this account therefore error , the lambda will exit with error
                bot_data[
                    'Error'] = f'This finding was found in account id {event_account_id}. The Lambda function is running in account id: {lambda_account_id}. Remediations need to be ran from the account there is the issue in.'
                output_message['Rules violations found'].append(bot_data.copy())
                continue

        else:  # Boto will default to default session if we don't need assume_role credentials
            boto_session = boto3.Session(region_name=message_data.get('region'))

        try:  ## Run the bot

            # Find and add Log.ic event time to the entity
            try:
                message['entity']['eventTime'] = next(json.loads(element['value'])['alertWindowStartTime']
                                                      for element in message['additionalFields']
                                                      if element.get('name') == 'logic_data' and
                                                      'alertWindowStartTime' in element.get('value'))
            except:
                print(f'{__file__} - Warning - Adding Log.ic event time to entity failed')
            # Add CloudAccount ID to entity argument
            entity = message['entity']
            entity['cloud_account_id'] = output_message['Account id']
            # Add executer arn, add assumed role arn to params in case they will be used by the bot.
            if 'function_arn' in message:
                params.append('exec_function_arn=%s' % message['function_arn'])
            if role_arn is not None:
                params.append('assumed_role_arn=%s' % role_arn)
            bot_msg = bot_module.run_action(boto_session, message['rule'], entity, params)
            bot_data['Execution status'] = 'passed'

        except ClientError as e:
            bot_msg = f"Unexpected client error: {e} \n"
            if 'AccessDenied' in e.response['Error']['Code']:
                bot_msg += f"Make sure your dome9CloudBots-RemediationFunctionRole is updated with the relevant permissions. The permissions can be found here: {permissions_link}. You can update them manually or relaunch the CFT stack as described here: {relaunch_stack} \n"

        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            bot_msg = f'Error while executing function {bot}. Error: {e} \nFor more details please see the CloudWatch logs. \n'
            bot_data['Execution status'] = 'failed'
            print(
                f'{__file__} Details: {" ".join(traceback.format_exception(exception_type, exception_object, exception_traceback))} \n')

        bot_data['Bot message'] = bot_msg
        output_message['Rules violations found'].append(bot_data.copy())

    # After the remediation functions finish, send the notification out.
    return post_to_sns
