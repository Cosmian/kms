# Configuring the .well-known file

General configuration instructions for Google client-side encryption is available at [this url](https://support.google.com/a/answer/10743588) in paragraph _(Option 1) To connect to your IdP using a `.well-known` file_

## Using Google as an Identity Provider

To use Google as an Identity Provider, you first need to create a dedicated client ID in the Google Cloud Console. Detailed instructions are available on the page referenced above in the section entitled _Create-a-client-id-for-google-identity_.

The general idea is to create a project, then in _APIs & Services > Credentials_, create a client ID for a web application.
This Client ID will be used in the `.well-known` file.

Once created the Client ID should look like this

![Create Client ID](./images/oauth-client-id-created-in-the-console.png)

!!! warning
    Do not forget to add <http://localhost:17899/authorization> in the Authorized redirect URIs list.
    It will allow the [Cosmian CLI](../kms_clients/index.md) to authenticate with Google.

The list of URLs for _Authorized origins_ and _Authorized redirect_ are available in the Google documentation above, in paragraph _Create a client ID for Google identity_.

### Generating the .well-known file

The format of the `.well-known` file is specified by [RFC 8259](https://tools.ietf.org/html/rfc8259)

```json
{
  "name": "Google identity for workspace client-side encryption",
  "client_id": "996739510374-au9fdbgp72dacrsag267ckg32jf3d3e2.apps.googleusercontent.com",
  "discovery_uri": "https://accounts.google.com/.well-known/openid-configuration",
  "grant_type": "implicit",
  "applications": {
    "drivefs": {
      "client_id": "947318989803-k88lapdik9bledfml8rr69ic6d3rdv57.apps.googleusercontent.com"
    },
    "drive-android": {
      "client_id": "313892590415-6lbccuf47cou4q45vanraqp3fv5jt9do.apps.googleusercontent.com"
    },
    "drive-ios": {
      "client_id": "313892590415-d3h1l7kl4htab916r6jevqdtu8bfmh9m.apps.googleusercontent.com"
    },
    "calendar-android": {
      "client_id": "313892590415-q84luo8fon5pn5vl8a6rppo1qvcd3qvn.apps.googleusercontent.com"
    },
    "calendar-ios": {
      "client_id": "313892590415-283b3nilr8561tedgu1n4dcm9hd6g3hr.apps.googleusercontent.com"
    },
    "gmail-android": {
      "client_id": "313892590415-samhd32i4piankgs42o9sit5e9dug452.apps.googleusercontent.com"
    },
    "gmail-ios": {
      "client_id": "313892590415-ijvjpbnsh0gauuunjgsdn64ngg37k6rc.apps.googleusercontent.com"
    },
    "meet-android": {
      "client_id": "313892590415-i06v47su4k03ns7ot38akv7s9ari5oa5.apps.googleusercontent.com"
    },
    "meet-ios": {
      "client_id": "313892590415-32ha2bvs0tr1b12s089i33o58hjvqt55.apps.googleusercontent.com"
    }
  }
}
```

`client_id` is the OAuth 2.0 client ID of the Google Workspace domain that is created using the Google Cloud Console


# Configuring a static web server to serve the .well-known file

The URL at which Google client-side encryption expects the `.well-known` file is on the link pointed by the red arrow below.

![URL of well-known file](./images/url-of-well-known-file.png)

Assuming your organization is on the domain `acme.com` (which should match that of your email address domain), the URL would be: `https://cse.acme.com/.well-known/cse-configuration`

## 1. Configure a server running Ubuntu 23.04

The server should be reachable using an external IP; configure your DNS so that a `A` record with value `cse.acme.com` points to that external IP address of the server.

Make sure ports 80 and 443 are open to external traffic on this machine. Access to port 80 can be closed at the end of this procedure.

## 2. Install `nginx` on the server

```sh
sudo apt update
sudo apt install nginx
```

## 3. Transfer your .well-known file

```sh
sudo mkdir /var/www/html/.well-known
sudo touch /var/www/html/.well-known/cse-configuration
sudo scp 'path_to_your_well_known_file' user@IP:/var/www/html/.well-known/cse-configuration"
```

The file will put your created `.well-known` file to you web server in order to expose it.

## 4. Configure `nginx` to serve the .well-known file

Since, the `.well-known` file is served from a different domain than the one used by Google client-side encryption,
CORS calls need to be enabled on NGINX to allow the browser to fetch the `.well-known` file.

Edit the file `/etc/nginx/sites-available/default` and add the following `location`:

```nginx
location /.well-known/ {
    root /var/www/html;
    # Allow CORS calls: see https://support.google.com/a/answer/10743588?hl=en
    add_header 'Access-Control-Allow-Origin' '*';
}
```

Then restart the `nginx` service

```sh
sudo systemctl restart nginx
```

Finally, verify that `nginx` is correctly serving the file by running

```sh
➜ curl http://localhost/.well-known/cse-configuration
```

## 5. Enable HTTPS with `certbot` and Lets's Encrypt

Install `certbot` on the machine using `snap` (the `snap` daemon should already be installed and activated on Ubuntu 23.04)

```sh
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
```

General instructions on installing `certbot` are available at [this URL](https://certbot.eff.org/lets-encrypt/ubuntufocal-nginx).

Get a certificate and configure `nginx`

```sh
sudo certbot --nginx
```

The command will ask you to provide an email address and a domain name. The domain name should be `cse.acme.com` (or whatever domain you chose in step 1).

That's it, the empty `.well-known` file should now be served using HTTPS. From another machine, verify that it is now available on the public address

```sh
➜ curl https://cse.acme.com/.well-known/cse-configuration
{}

```

Port 80 can now be closed on the machine (or `nginx` configuration can be updated to redirect HTTP requests to HTTPS)

## 6. Enable CORS calls

The `.well-known` file is served from a different domain than the one used by Google client-side encryption. CORS calls need to be enabled on the server to allow the browser to fetch the `.well-known` file.

Edit the file `/etc/nginx/sites-available/default` and add the following at the top of the file (before the `server` block):

```nginx
# Allow CORS calls: see https://apps.google.com/supportwidget/articlehome?hl=en&article_url=https%3A%2F%2Fsupport.google.com%2Fa%2Fanswer%2F10743588%3Fhl%3Den&assistant_id=generic-unu&product_context=10743588&product_name=UnuFlow&trigger_context=a
add_header 'Access-Control-Allow-Origin' '*';
```

Then restart the `nginx` service

```sh
sudo systemctl restart nginx
```

## 7. Optional: download the .well-known file as a proper JSON

The Client-side encryption service does not require this setting to work properly. However, it is useful to be able to download the `.well-known` file as a proper JSON object when viewing it in a browser.

To do so, the `content-type` header of the response must be set to `application/json`. Edit the file `/etc/nginx/sites-available/default` and add the following inside the `server` block that serves the HTTPS requests:

```nginx
location /.well-known/ {
    default_type application/json;
}
```

Then restart the `nginx` service

```sh
sudo systemctl restart nginx
```
