AWS Assume daemon
=================

This script automatically assumes every 15 minutes the specified role using a
Yubikey as MFA (multi factor authentication) and updates `~/.aws/credentials`.

As long as you've got your yubikey connected to your computer you'll never
have to enter a second factor authentication code for the aws cli. As other
tools / libraries (boto3) use `~/.aws/credentials` as well you don't have to
enter a token for these either.

Usage
=====

You can install aws_assume using pip (`pip install aws_assume`), I recommend
to install aws_assume using poetry (`poetry install aws_assume`) or in a
virtualenv.

Your `~/.aws/credentials` should contain your credentials and a profile with
the the keys `aws_access_key_id`, `aws_secret_access_key` and
`aws_session_token`.

For example:

`~/.aws/credentials`

```ini
[default]
aws_access_key_id = ...(your key id)...
aws_secret_access_key = ...(your access key)...

[profile]
aws_access_key_id = ...(placeholder, can be anything)...
aws_secret_access_key = ...(placeholder, can be anything)...
aws_session_token = ...(placeholder, can be anything)...
```

Your `~/.aws/credentials` will be updated in place, only the specified profile
section should be touched (your comments will be safe).

Older versions are rotated up to 5 items.

Next `_assume` should be started with the following arguments:

```bash
_assume --rolearn ... --oath_slot=... --serialnumber=... --profile_name=... --access-key-id=... --secret-access-key=... --mfa-session-duration=...
```

Argument                 | Description
-------------------------|-------------------------------------
`--rolearn`              | arn of the role you'd like to assume
`--oath_slot`            | oath slot on your yubikey
`--serialnumber`         | serial number of your MFA
`--profile_name`         | profile used in `~/.aws/credentials`
`--access-key-id`        | access key (as obtained from IAM console)
`--secret-access-key`    | secret access key (as obtained from IAM console)
`--mfa-session-duration` | duration (in seconds) for MFA session

You should only run one `_assume` process per profile, I use systemd for
starting `_assume`, by using the following unit file:

`~/.config/systemd/user/aws_assume@.service`

```ini
[Unit]
Description=Amazon Web Services token daemon

[Service]
Type=simple
ExecStart=%h/bin/_assume --rolearn='...%i...' --oath_slot=... --serialnumber=... --profile_name='...%i...' --access-key-id='...' --secret-access-key='...'
Restart=on-failure

[Install]
WantedBy=default.target
```

And reload systemd using `systemctl --user daemon-reload`, start `_assume` using
`systemctl --user start aws_assume@...`

If you're not so fortunate to have systemd you can also use something like
`supervisord` to start `_assume`.

`~/supervisord.conf`

```ini
[supervisord]

[supervisorctl]
serverurl=unix:///home/user/supervisord.sock

[unix_http_server]
file=/home/user/supervisord.sock

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[program:assume-...]
command=/home/user/bin/_assume --rolearn=... --oath_slot=... --serialnumber=... --profile_name=... --access-key-id=... --secret-access-key=...
autorestart=true
```

Start supervisord using `supervisord -c supervisor.conf` and start assume using
`supervisorctl -c supervisor.conf start assume-...`.
