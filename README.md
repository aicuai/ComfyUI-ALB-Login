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
