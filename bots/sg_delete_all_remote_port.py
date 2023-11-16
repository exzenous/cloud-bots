"""
## sg_delete_all_remote_port
What it does: Deletes all rules on a security group with a scope(cidr) containing or equal to a given scope,
             port and protocol are optional

Usage: sg_delete_all_remote_port

Parameters:
    scope: a.b.c.d/e
    direction: inbound/ outbound
    port: number/ *
    protocol: TCP/ UDP/ *
-When '*' is any value of the parameter

Notes :
    - the bot deletes the rule without splitting ports ( do not create new rules without the deleted port)
      for deleting rule with split use - sg_single_rule_delete bot .
    -  before running this bot, ensure that your applications will work correctly without those rules
    - if a port is in a port range the rule wont be deleted ! use * on port parameter to delete the rule for any port
Limitations: IPv6 is not supported

"""

import bots_utils as utils

PORT_TO = 'portTo'
PORT_FROM = 'port'
PROTOCOL = 'protocol'
SCOPE = 'scope'
ALL_TRAFFIC_PORT = 0
ALL_TRAFFIC_PROTOCOL = '-1'



def run_action(boto_session, rule, entity, params):
    text_output = 'Run Bot sg_delete_all_remote_port. '
    # Get SecurityGroup id
    sg_id = entity['id']

    all_params = [["0.0.0.0/0", "inbound", "22", "*"], ["0.0.0.0/0", "inbound", "3389", "*"], ["0.0.0.0/0", "inbound", "0", "*"]]

    for my_params in all_params:
        # Param retrieving
        try:
            scope, direction, port, protocol = my_params[0:4]  # get params

        except Exception as e:
            text_output = text_output + f'Params handling error. Please check parameters and try again. Error: {e}'
            raise Exception(text_output)
        #
        ec2_resource = boto_session.resource('ec2')
        #
        sg = ec2_resource.SecurityGroup(sg_id)
        port = str(port)
        for rule in entity[f'{direction}Rules']:
            if utils.is_scope_contained_by_other_ipv4(scope, rule[SCOPE]):
                # rule have overlap ip's with the given scope
                if port == '*' or int(port) == rule[PORT_FROM] == rule[PORT_TO]:
                    if protocol.lower() == rule[PROTOCOL].lower() or protocol == '*':
                        if rule[PROTOCOL] == 'ALL':
                            rule[PROTOCOL] = ALL_TRAFFIC_PROTOCOL  # '-1'
                        text_output = text_output + utils.stringify_rule(rule) + 'rule was found in security group with port in range; '
                        text_output = utils.delete_sg(sg, sg_id, rule, direction, text_output)

            else:
                continue

    return text_output
