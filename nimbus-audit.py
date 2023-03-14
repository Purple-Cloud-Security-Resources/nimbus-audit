import boto3
import logging

def check_bucket_encryption(bucket_name):
    # initialize S3 client
    s3 = boto3.client('s3')

    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        if 'ServerSideEncryptionConfiguration' in response:
            sse_config = response['ServerSideEncryptionConfiguration']
            if 'Rules' in sse_config:
                rules = sse_config['Rules']
                for rule in rules:
                    if rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'aws:kms':
                        return (f"Bucket {bucket_name} is encrypted with SSE-KMS using key {rule['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID']}")
                    elif rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'AES256':
                        return (f"Bucket {bucket_name} is encrypted with SSE-S3")
                    else:
                        return (f"Bucket {bucket_name} is encrypted with an unsupported algorithm")
            else:
                return (f"Bucket {bucket_name} has no encryption rules")
        else:
            return logging.warning(f"Bucket {bucket_name} has no encryption configuration")

    except Exception as e:
        return logging.warning(f"Error checking encryption settings for bucket {bucket_name}: {e}")

def check_bucket_versioning(bucket_name):
    # initialize S3 client
    s3 = boto3.client('s3')

    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        ##if 'Status' in response == 'Enabled':
        if 'Status' in response and response['Status'] == 'Enabled':
                return f"Bucket {bucket_name} has versioning enabled"
        else:
            return f"Bucket {bucket_name} has no versioning configuration."
    except Exception as e:
        return f"Error checking versioning settings for bucket {bucket_name}: {str(e)}"


def check_mfa_delete(bucket_name):
    # initialize S3 client
    s3 = boto3.client('s3')
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        if 'MFADelete' in response and response['MFADelete'] == 'Enabled':
            return f"MFA Delete is enabled for {bucket_name}"
        elif 'MFADelete' not in response:
            return f"MFA Delete is not enabled for {bucket_name}"
    except Exception as e:
        return f"Error checking versioning settings for bucket {bucket_name}: {str(e)}"

def s3_audit():
    # set up logging
    logging.basicConfig(filename='s3_audit.log', level=logging.INFO)

    # initialize S3 client
    s3 = boto3.client('s3')

    try:
        # get list of all buckets
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]

        # loop through each bucket and check encryption settings
        for bucket_name in buckets:
            resultencrypt = check_bucket_encryption(bucket_name)
            logging.info(resultencrypt)
            print(resultencrypt)
            bucketver = check_bucket_versioning(bucket_name)
            logging.info(bucketver)
            print(bucketver)
            mfa_del=check_mfa_delete(bucket_name)
            logging.info(mfa_del)
            print(mfa_del)

        logging.info("S3 encryption audit completed successfully")

    except Exception as e:
        logging.error(f"Error retrieving list of buckets: {e}")


if __name__ == "__main__":
    s3_audit()
