import os
import json
import re
from time import time
import hashlib
import base64
from datetime import datetime
import blake3
from simple_said import saidify # https://github.com/dane-git/simple-said.git


ROOT_FILE = '../spec/spec.md'
with open(ROOT_FILE, "r", encoding="utf-8") as file:
  DATA = file.read()


def file_to_b64(file_path):
    """
    Read raw bytes from a file and store them in a JSON-compatible format (Base64 encoded).
    
    :param file_path: Path to the file to be read.
    :return: Base64-encoded file content.
    """
    try:
        with open(file_path, 'rb') as f:
            raw_bytes = f.read()
            base64_encoded = base64.b64encode(raw_bytes).decode('utf-8')  # Encode and convert to UTF-8 string
        return  base64_encoded
    except Exception as e:
        return f"Error reading file: {e}"  
      
def calculate_blake3_256(file_path):
    """
    Calculate the BLAKE3 256-bit hash of a file.

    :param file_path: Path to the file.
    :return: Hexadecimal hash of the file.
    """
    try:
        hasher = blake3.blake3()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):  # Read the file in chunks
                hasher.update(chunk)
        return hasher.digest() # 256 bits = 32 bytes
    except FileNotFoundError:
        return f"File not found: {file_path}"
    except IOError as e:
        return f"IOError: {e}"
    
def base64_to_file(base64_string, output_path):
    """
    Decode a Base64 string and write it back as a UTF-8 file.
    
    :param base64_string: Base64-encoded string of the file content.
    :param output_path: Path where the decoded file will be saved.
    """
    try:
        # Decode the Base64 string into raw bytes
        raw_bytes = base64.b64decode(base64_string)
        
        # Write the bytes back to a file as UTF-8
        with open(output_path, 'wb') as f:
            f.write(raw_bytes)
        
        print(f"File successfully written to: {output_path}")
    except Exception as e:
        print(f"Error writing file: {e}")
        
def calculate_file_hash(file_path, hash_algo='sha256'):
    """
    Calculate the hash of a single file using the specified hashing algorithm.
    
    :param file_path: Path to the file to be hashed.
    :param hash_algo: Hashing algorithm to use (default: 'sha256').
    :return: Hexadecimal hash of the file.
    """
    hash_func = hashlib.new(hash_algo)
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
    except FileNotFoundError:
        return f"File not found: {file_path}"
    except IOError as e:
        return f"IOError: {e}"
      
    return hash_func.hexdigest()
  
def get_file_info(file_path):
    """
    Get file's base name, extension, creation time, and modified time.

    :param file_path: Path to the file.
    :return: Dictionary with file details.
    """
    if not os.path.isfile(file_path):
        return {"error": "File not found"}

    file_info = {}
    try:
        # Get base name and extension
        file_info['base_name'] = os.path.basename(file_path)
        file_info['extension'] = os.path.splitext(file_path)[1]

        # Get creation time
        creation_time = os.path.getctime(file_path)
        file_info['creation_time'] = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')

        # Get modified time
        modified_time = os.path.getmtime(file_path)
        file_info['modified_time'] = datetime.fromtimestamp(modified_time).strftime('%Y-%m-%d %H:%M:%S')

    except Exception as e:
        file_info['error'] = str(e)

    return file_info




  
file_sha256 = calculate_file_hash(ROOT_FILE)
raw_b64 = file_to_b64(ROOT_FILE)  
file_info = get_file_info(ROOT_FILE)
run_time = int(time())

calculations = {}
meta  = {
  'd': f'{"#"*44}', 
  'run_time': run_time,
  'file_sha256': file_sha256,
  **file_info,
  'raw_b64': raw_b64,
  }
print(meta['d'])


def extract_code_blocks(data):

  code_blocks = {}
  pattern = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)
  
  matches = pattern.findall(data)
  for idx, (block_type, block_content) in enumerate(matches):
    code_blocks[idx] = {
      "type": block_type.strip(),
      "content": block_content.strip()
    }

  return code_blocks




def preprocess_and_wrap_json(content):
  """
  Preprocess and wrap partial JSON to ensure it forms a valid structure.
  Handles issues like newlines before brackets and standalone keys.

  Args:
      content (str): The raw JSON-like string.

  Returns:
      str: Preprocessed JSON string.
  """
  # Remove trailing commas
  content = re.sub(r',\s*([\}\]])', r'\1', content)

  # Replace invalid tokens like '***' with null
  content = re.sub(r'\*\*\*', 'null', content)

  # Handle keys not wrapped in a valid structure
  # Wrap incomplete top-level keys into an object
  if not content.strip().startswith(('{', '[')):
      content = '{' + content.strip() + '}'

  # Handle newlines before opening brackets
  content = re.sub(r'(\S):\s*\n\s*([\{\[])', r'\1: \2', content)

  return content

def parse_partial_json(content):
  """
  Attempts to parse partial JSON content with preprocessing.

  Args:
      content (str): The raw JSON-like string.

  Returns:
      dict: Parsed JSON dictionary if successful.
  """
  try:
    # Preprocess and parse the JSON
    cleaned_content = preprocess_and_wrap_json(content)
    return json.loads(cleaned_content)
  except json.JSONDecodeError as e:
    # Re-raise for debugging context
    raise e
    

## get the code blocks:
blocks = extract_code_blocks(DATA)
# Process each block and handle JSON errors
for k in blocks:
  if blocks[k]['type'] == 'json' or blocks[k]['type'] =='python':
    try:
      blocks[k]['data'] = json.loads(blocks[k]['content'])
    except json.JSONDecodeError as e1:
      try:
        # Attempt to clean and parse partial JSON
        blocks[k]['data'] = parse_partial_json(blocks[k]['content'])
      except json.JSONDecodeError as e2:
        print('*'*88)
        print('FAIL2')
        raise ("ERROR")


# ============================================================================================================
def flatten_dict(d, parent_key='', sep='.'):
    """
    Flattens a nested dictionary into a single-level dictionary with dot-separated keys.
    Handles nested dictionaries and lists.

    Args:
        d (dict): The dictionary to flatten.
        parent_key (str): The base key string for recursion (used internally).
        sep (str): The separator to use for flattened keys.

    Returns:
        dict: A flattened dictionary.
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            # Recurse into nested dictionaries
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # Flatten list by adding index to the key
            for i, item in enumerate(v):
                items.extend(flatten_dict({str(i): item}, new_key, sep=sep).items())
        else:
            # Base case: add the key-value pair
            items.append((new_key, v))
    return dict(items)





def list_contains_substring_list(_list, sub_list):
    for elem in _list:
        for s in sub_list:
            if s in elem:
                return True
    return False
    
def dict_has_key(keyList, k):
    # keyList = _list.split('.')
    all_keys = []
    for _k in keyList:
        if '.' in _k:
            # print('split', _k)
            these_keys = _k.split('.')
            # print(these_keys)
            for level, ke in enumerate(these_keys):
                all_keys.append([ke, level])
        else:
            all_keys.append([_k, 0])
    for elem, level in all_keys:
        if k == elem:
            return True, level
    return False, -1
    
saidify_exclude = ['$schema', '$id', 'properties', 'oneOf']

def to_int(v):
    try:
        return int(v)
    except:
        return v
    

from copy import deepcopy
for ind, k in enumerate(blocks):
  full = None
  sads = None
  if 'data' in blocks[k]:
      
    data = blocks[k]['data']
    flattened = flatten_dict(data)
    if '$id' in data:
        
      saidified = saidify.saidify(data, label='$id', compactify=True)
      blocks[k]['basic_said']  = saidified['version_1_said_calc']
      blocks[k]['compact_said']  = saidified['final_said']
      all_paths = saidified['paths']
      sads = saidified['sads']
      full = saidify.construct_partial(all_paths, sads,  saidified['label'])
      blocks[k]['full'] = full
    if list_contains_substring_list(flattened,saidify_exclude):
      continue
    flat_keys = list(flattened.keys())
    _path = []

    if 'd' in data:
      # said, _ =  saidify.saidify(data,  compactify = True)
      saidified = saidify.saidify(data, compactify=True)
      blocks[k]['basic_said']  = saidified['version_1_said_calc']
      blocks[k]['compact_said']  = saidified['final_said']
  
    elif dict_has_key(flat_keys,'d')[0]:
        
      _, level = dict_has_key(flat_keys,'d')

      _dict= deepcopy(data)
      nest_k = flat_keys[0].split('.')
      this = _dict
      
      for i in range(level):
        this_key = to_int(nest_k[i])
        _path.append(this_key)
        this = this[this_key]

      saidified = saidify.saidify(this,  compactify=True)
      blocks[k]['compact_said']  = saidified['final_said']
    if len(saidified['paths']) > 1:
      all_paths = saidified['paths']
      sads = saidified['sads']
      full = saidify.construct_partial(all_paths, sads, saidified['label'])
      blocks[k]['full'] = full
      blocks[k]['full_path'] = _path
        
calculations['blocks'] = blocks
_meta = saidify.saidify(meta, label='d', compactify=True)
meta = _meta['non_compact']
calculations['meta'] = meta
# base64_to_file(meta['raw_b64'], 'test_file_convert.md')
# print(calculations)
outfile = f'./results/{str(run_time)}_said_calulations.json'
with open(outfile, 'w') as json_file:
    json.dump(calculations, json_file, indent=4) 
print(os.getcwd())
print(outfile,' written')