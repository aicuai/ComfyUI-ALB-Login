# ComfyUI-ALB-Login

Auth library to inspect token provided by ALB to protect ComfyUI.

Built for [ComfyUI on AWS](https://github.com/aws-samples/cost-effective-aws-deployment-of-comfyui).

This library inspects user info and redirect to the specified URL if the user is not in the required cognito group.

## Installation

In the directory ComfyUI/custom_nodes/, git clone this repo, and do pip install -r requirements.txt in the repo's directory.

## Configuration

You can set redirect URL and required group with environment variables.

```
REDIRECT_URL=https://example.com/membership
REQUIRED_GROUP=membership
```

Other required environment variables are:

```
AWS_REGION=ap-northeast-1
COGNITO_USER_POOL_ID=ap-northeast-1_1234567890
COGNITO_CLIENT_ID=1234567890
```

You can set these environment variables [here](https://github.com/aws-samples/cost-effective-aws-deployment-of-comfyui/blob/main/comfyui_aws_stack/construct/ecs_construct.py#L131) if you are using [ComfyUI on AWS](https://github.com/aws-samples/cost-effective-aws-deployment-of-comfyui).