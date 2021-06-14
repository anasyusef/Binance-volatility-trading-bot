from sys import exit
from botocore.exceptions import ClientError, NoCredentialsError

import boto3
import json


def get_secret():

    secret_name = "Binance"
    region_name = "eu-west-2"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "DecryptionFailureException":
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "InternalServiceErrorException":
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "InvalidParameterException":
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "InvalidRequestException":
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "ResourceNotFoundException":
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        if "SecretString" in get_secret_value_response:
            secret = get_secret_value_response["SecretString"]
            parsed_secret = json.loads(secret)
            return [
                parsed_secret.get("binance_access_key"),
                parsed_secret.get("binance_secret_key"),
            ]
        return None, None


def load_correct_creds(creds):
    access_key, secret_key = None, None
    try:
        access_key, secret_key = get_secret()
        print("Using AWS credentials")
        return access_key, secret_key
    except NoCredentialsError:
        print(
            "Couldn't get credentials from AWS Secrets Manager. Falling back to getting credentials from creds.yml"
        )
    try:
        print("Using creds.yml file")
        return creds["prod"]["access_key"], creds["prod"]["secret_key"]

    except TypeError as te:
        message = "Your credentials are formatted incorectly\n"
        message += f"TypeError:Exception:\n\t{str(te)}"
        exit(message)
    except Exception as e:
        message = "oopsies, looks like you did something real bad. Fallback Exception caught...\n"
        message += f"Exception:\n\t{str(e)}"
        exit(message)


def test_api_key(client, BinanceAPIException):
    """Checks to see if API keys supplied returns errors

    Args:
        client (class): binance client class
        BinanceAPIException (clas): binance exeptions class

    Returns:
        bool | msg: true/false depending on success, and message
    """
    try:
        client.get_account()
        return True, "API key validated succesfully"

    except BinanceAPIException as e:

        if e.code in [-2015, -2014]:
            bad_key = "Your API key is not formatted correctly..."
            america = "If you are in america, you will have to update the config to set AMERICAN_USER: True"
            ip_b = "If you set an IP block on your keys make sure this IP address is allowed. check ipinfo.io/ip"

            msg = f"Your API key is either incorrect, IP blocked, or incorrect tld/permissons...\n  most likely: {bad_key}\n  {america}\n  {ip_b}"

        elif e.code == -2021:
            issue = "https://github.com/CyberPunkMetalHead/Binance-volatility-trading-bot/issues/28"
            desc = "Ensure your OS is time synced with a timeserver. See issue."
            msg = f"Timestamp for this request was 1000ms ahead of the server's time.\n  {issue}\n  {desc}"
        elif e.code == -1021:
            desc = "Your operating system time is not properly synced... Please sync ntp time with 'pool.ntp.org'"
            msg = f"{desc}\nmaybe try this:\n\tsudo ntpdate pool.ntp.org"
        else:
            msg = "Encountered an API Error code that was not caught nicely, please open issue...\n"
            msg += str(e)

        return False, msg

    except Exception as e:
        return False, f"Fallback exception occured:\n{e}"
