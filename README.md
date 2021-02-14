AWS Session daemon
=================

This script automatically gets an MFA authenticated session using a Yubikey as MFA (multi factor authentication) and updates
`~/.aws/credentials`.

As long as you've got your yubikey connected to your computer you'll never have to enter a second factor authentication code for the aws
cli. As other tools / libraries (boto3) use `~/.aws/credentials` as well you don't have to enter a token for these either.

Usage
-----

You can install `aws-session-daemon` using pip (`pip install aws-session-daemon`), I recommend to install `aws-session-daemon` using poetry
(`poetry install aws-session-daemon`) or in a virtualenv.

Your `~/.aws/credentials` should contain your credentials and a profile with the the keys `aws_access_key_id`,
`aws_secret_access_key` and `aws_session_token`.

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

Your `~/.aws/credentials` will be updated in place, only the specified profile section should be touched (your comments will be safe).

Older versions are rotated up to 5 items.

Next `aws-session-daemon` should be started with the following arguments:

```bash
aws-session-daemon --rolearn ... --oath_slot=... --serialnumber=... --profile_name=... --access-key-id=... --secret-access-key=... --mfa-session-duration=...
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
`--credentials-section`  | you can specify a different section than default in `~/.aws/credentials`

You should only run one `aws-session-daemon` process per profile, I use systemd for starting `aws-session-daemon`, by using the
following unit file:

`~/.config/systemd/user/aws-session-daemon@.service`

```ini
[Unit]
Description=Amazon Web Services token daemon

[Service]
Type=simple
ExecStart=%h/bin/aws-session-daemon --rolearn='...%i...' --oath_slot=... --serialnumber=... --profile_name='...%i...' --access-key-id='...' --secret-access-key='...'
Restart=on-failure

[Install]
WantedBy=default.target
```

And reload systemd using `systemctl --user daemon-reload`, start `aws-session-daemon` using `systemctl --user start aws-session-daemon@...`

If you're not so fortunate to have systemd you can also use something like `supervisord` to start `aws-session-daemon`.

`~/supervisord.conf`

```ini
[supervisord]

[supervisorctl]
serverurl=unix:///home/user/supervisord.sock

[unix_http_server]
file=/home/user/supervisord.sock

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[program:session-daemon-...]
command=/home/user/bin/aws-session-daemon --rolearn=... --oath_slot=... --serialnumber=... --profile_name=... --access-key-id=... --secret-access-key=...
autorestart=true
```

Start supervisord using `supervisord -c supervisor.conf` and start session-daemon using
`supervisorctl -c supervisor.conf start session-daemon-...`.
