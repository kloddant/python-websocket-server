# python-websocket-server
A Python websocket server with a json api.

## Quickstart
Download everything and double-click start_server.bat.  Then open javascript_chat_client.html in two different windows, and start chatting with yourself.

## API
All api requests are sent to the server via json encoded as strings, and all will get responses returned as json strings.  All of them have a required function parameter, which specifies what they are trying to do.  All of them also have an optional callback parameter which does nothing on the server but will be returned in the server's response so that you can then activate another function on the client side.  Here are some example requests:

Send a message to another client.

    {
        "function": "send_message",
        "recipient_ids": [],
        "message": "message",
        "callback": "",
    }
    
Retrieve a dictionary of every public client, including their id, ip, port, and custom variables.

    {
        "function": "retrieve_clients",
        "callback": "",
    }
    
Specify custom variables for a client, such as their name.

    {
        "function": "set_custom_variables",
        "custom_variables": {"name":"Bob"},
        "callback": "",
    }
    
Set a client's privacy to "public" or "private".

    {
        "function": "set_privacy",
        "privacy": "public",
        "callback": "",
    }
  
Allow an ip address to contact a private client.

    {
        "function": "allow_ip",
        "ip": "127.0.0.1",
        "callback": "",
    }  
    
Block an ip address from contacting a client.

    {
        "function": "block_ip",
        "ip": "127.0.0.1",
        "callback": "",
    }
    
Ban an ip address from contacting anyone for as long as the server is up.

    {
        "function": "ban_ip",
        "ip": "127.0.0.1",
        "callback": "",
    }
