import sys, site
site.addsitedir('/srv/nbgr-x/env/local/lib/python2.7/site-packages')

sys.path.insert(0,'/srv/nbgr-x')

activate_env = "/srv/nbgr-x/env/bin/activate_this.py"
execfile(activate_env, dict(__file__=activate_env))

from nbgr_x import app as application

