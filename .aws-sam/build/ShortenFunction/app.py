import json
import os
import string
import random
import boto3

dynamodb = boto3.resource("dynamodb")
table_name = os.environ.get("TABLE_NAME", "UrlShortenerTable")
table = dynamodb.Table(table_name)

def generate_code(length=6):
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))

def create_url(event, context):
    try:
        body = json.loads(event.get("body", "{}"))
        long_url = body.get("url")
        if not long_url:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Missing 'url' field in request body"})
            }

        short_code = generate_code()
        table.put_item(
            Item={
                "short_code": short_code,
                "original_url": long_url,
                "clicks": 0
            }
        )

        domain = event.get("requestContext", {}).get("domainName", "")
        short_url = f"https://{domain}/{short_code}" if domain else short_code

        return {
            "statusCode": 201,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "message": "URL shortened successfully",
                "short_code": short_code,
                "short_url": short_url,
                "original_url": long_url
            })
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(e)})
        }

def redirect_url(event, context):
    try:
        path_params = event.get("pathParameters") or {}
        short_code = path_params.get("short_code")
        if not short_code:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Missing short code"})
            }

        response = table.get_item(Key={"short_code": short_code})
        item = response.get("Item")

        if not item:
            return {
                "statusCode": 404,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Short URL not found"})
            }

        table.update_item(
            Key={"short_code": short_code},
            UpdateExpression="SET clicks = clicks + :val",
            ExpressionAttributeValues={":val": 1}
        )

        return {
            "statusCode": 302,
            "headers": {
                "Location": item["original_url"]
            }
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(e)})
        }
