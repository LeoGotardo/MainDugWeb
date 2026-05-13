import sys, os
from dotenv import load_dotenv

_src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
load_dotenv(os.path.join(_src_dir, '.env'))
sys.path.insert(0, _src_dir)

from app import app
