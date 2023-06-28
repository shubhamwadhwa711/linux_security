### Create virtual environment python 3.9
```
virtualenv .venv --python=python3.9
```

### Activate virtual environment
```
source .venv/bin/activate
```

### Install packages
```
pip install -r requirements.txt
```

### Update the config for scripts
Please make sure that you have changed the configs inside `config.ini` depending on your machine before execute the scripts
- `[mysql]` section for database
- `script-01` section for introtext and fulltext script
- `script-02` section for URLs script

### Run 01-introtext-fulltext-script.py for introtext and fulltext fields
- If you would like to run the script without saving database. Use this command:
```
python 01-introtext-fulltext-script.py
```
- Use this command if you want to check for specific ID
```
python 01-introtext-fulltext-script.py --id 113785
```
- Use this command if you want to commit the changes into database. This will generate `store_state_file` file that is defined in `config.ini > [script-01]` to store the processing state.
```
python 01-introtext-fulltext-script.py --commit
```

### Run 02-urls-script.py for URLs field
- If you would like to run the script without saving database. Use this command:
```
python 02-urls-script.py
```
- Check for specific ID
```
python 02-urls-script.py --id 113785
```
- Use this command if you want to commit the changes into database. This will generate `store_state_file` file that is defined in `config.ini > [script-02]` to store the processing state.
```
python 02-urls-script.py --commit
```

### Run 03-timeout-script.py for more checking
After executed 2 scripts above, these files (01.timeout-urls.json, 02.timeout-urls.json) will be generated automatically for Timeout error. In case we need to recheck these URLs to make sure those still working. Please run command below

- Without commit database
```
python 03-timeout-script.py --file 01.timeout-urls.json --timeout 10 (For checking URLs that are generated by script 01)
python 03-timeout-script.py --file 02.timeout-urls.json --urla --timeout 10 (For checking URLs that are generated by script 02)
```

- With commit database
```
python 03-timeout-script.py --file 01.timeout-urls.json --timeout 10 --commit (For checking URLs that are generated by script 01)
python 03-timeout-script.py --file 02.timeout-urls.json --urla --timeout 10 --commit (For checking URLs that are generated by script 02)
```
