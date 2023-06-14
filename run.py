import os
from app import create_app
from OpenSSL import SSL

if __name__ == '__main__':

    app = create_app()
    
    
    app.run()
