# Hook for the pybitcointools package
from PyInstaller.utils.hooks import collect_data_files
datas = collect_data_files('pycryptotools')
