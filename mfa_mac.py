'''
The script creates temporary security credentials that
one can use to access AWS via API, using user's MFA tokens.
UP THE IRONS!
'''
import shutil
import os
from datetime import datetime
import boto3
from botocore.exceptions import ClientError, ParamValidationError

# Constant variables
ACCOUNT_MAIN = "123456789012" # A 12-digit number
ACCOUNTS = { # Containing all the accounts to assume-role to
    'account-a': '000011112222',
    'account-b': '333344445555'
}
OUTPUT_FORMT = "" # Accepted values are: json, table, text, yaml, yaml-stream; default: json
PROFILE_CREDENTIALS_RETRIES = 3 # Modify this for number of retries per account
REGION_PRIMARY=""
REGION_SECONDARY=""
ROLE_DURATION = 900 # Min: 900; Max: 43200 (depending on max session duration setting for role)
ROLE_NAME = ""
CURRENT_TIME = datetime.now().strftime("%Y%m%d%H%M%S") # Optional for 'credentials' file backup
USER = os.getlogin() # For current user
USER_ACCESS_KEY = ""
USER_SECRET_KEY = ""

# Clients
STS_CLIENT = boto3.client('sts')

def main():
    '''
    Builds the 'credentials' file.
    '''
    # Paths
    credentials_file_path="/Users/" + USER + \
    "/.aws/credentials" # 'credentials' file location for a Mac user
    credentials_file_path_bak="/Users/" + USER + \
    "/credentials_" + CURRENT_TIME # Optional for 'credentials' file backup

    # The default section of the 'credentials' file
    default_config = "[default]\n" \
    "output=" + OUTPUT_FORMT + "\n" \
    "region=" + REGION_PRIMARY + "\n" \
    "aws_access_key_id=" + USER_ACCESS_KEY + "\n" \
    "aws_secret_access_key=" + USER_SECRET_KEY + "\n"

    # Backing up the current 'credentials' file
    shutil.copy(credentials_file_path, credentials_file_path_bak)

    # Appending credentials for accounts
    credentials_file = open(credentials_file_path, "r+")
    credentials_file.truncate(0)
    credentials_file.write(default_config)
    for profile_name in ACCOUNTS:
        profile_number = ACCOUNTS[profile_name]
        retry = 0
        profile_credentials = ""
        while retry < PROFILE_CREDENTIALS_RETRIES:
            try:
                profile_credentials = assume_account_role(profile_name, profile_number)
                break
            except (ParamValidationError, ClientError) as error:
                retry += 1
                print(error)
        parsed_credentials = parse_credentials(profile_credentials)
        profile_section = prepare_profile(parsed_credentials, profile_name)
        try:
            credentials_file.write(profile_section)
        except TypeError:
            pass
    credentials_file.close()


def assume_account_role(profile_name, profile_number):
    '''
    Performs the actual 'AssumeRole' to an account.
    Receives 'profile_name' and 'profile_number'.
    Returns a set of temporary security credential.
    '''
    token_code = input("Insert token for " + profile_name + ":\n")
    role_arn = "arn:aws:iam::" + profile_number + ":role/" + ROLE_NAME
    serial_number = "arn:aws:iam::" + ACCOUNT_MAIN + ":mfa/" + USER
    credentials = STS_CLIENT.assume_role(
        RoleArn=role_arn,
        RoleSessionName=ROLE_NAME,
        DurationSeconds=ROLE_DURATION,
        SerialNumber=serial_number,
        TokenCode=token_code
    )
    return credentials


def parse_credentials(profile_credentials):
    '''
    Parses the temporary security credential.
    Receives 'profile_credentials'.
    Returns dict of needed 'parsed_credentials'.
    '''
    try:
        access_key_id = profile_credentials['Credentials']['AccessKeyId']
        secret_access_key = profile_credentials['Credentials']['SecretAccessKey']
        session_token = profile_credentials['Credentials']['SessionToken']
        parsed_credentials = {
            'aws_access_key_id': access_key_id,
            'aws_secret_access_key': secret_access_key,
            'aws_session_token': session_token
        }
    except TypeError:
        pass
    try:
        return parsed_credentials
    except UnboundLocalError:
        pass


def prepare_profile(parsed_credentials, profile_name):
    '''
    Receives 'parsed_credentials' and 'profile_name'.
    Returns formated current 'profile_section' for the 'credentials' file.
    '''
    try:
        profile_section = "[" + profile_name + "]\n" \
        "output=" + OUTPUT_FORMT + "\n" \
        "region=" + REGION_PRIMARY + "\n" \
        "aws_access_key_id=" + parsed_credentials['aws_access_key_id'] + "\n" \
        "aws_secret_access_key=" + parsed_credentials['aws_secret_access_key'] + "\n" \
        "aws_session_token=" + parsed_credentials['aws_session_token'] + "\n"
    except TypeError:
        pass
    try:
        return profile_section
    except UnboundLocalError:
        pass


main ()
