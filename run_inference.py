# run_inference.py

import json
import os
import argparse
import re
import logging
from datetime import datetime
from typing import Dict, Any, List
from collections import defaultdict

from openai import OpenAI
from tqdm import tqdm

try:
    from ioc_finder import find_iocs
    from iocparser import IOCParser
except ImportError:
    print("Error: Missing required libraries for T1 processing. Please run: pip install ioc-finder iocparser")
    exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

TASK_PARAMETERS = {
    "T1": {"max_tokens": 1024, "top_p": 0.95, "temperature": 0.7, "top_k": 30},
    "T2": {"max_tokens": 50, "top_p": 0.95, "temperature": 0.7, "top_k": 30},
    "T3": {"max_tokens": 20, "top_p": 0.95, "temperature": 0.7, "top_k": 30},
    "T4": {"max_tokens": 20, "top_p": 0.95, "temperature": 0.7, "top_k": 30}
}


def clean_paragraph(paragraph: str) -> str:
    """Defangs URLs and cleans up common artifacts."""
    if not isinstance(paragraph, str):
        return ""
    paragraph = paragraph.encode("utf-8").decode()
    paragraph = paragraph.replace("[.]", ".")
    paragraph = paragraph.replace(".]", ".")
    paragraph = paragraph.replace("\[.\]", ".")
    paragraph = paragraph.replace("[:]", ":")
    paragraph = paragraph.replace("hxxps", "https")
    paragraph = paragraph.replace("hXXps", "https")
    paragraph = paragraph.replace("hXXp", "http")
    paragraph = paragraph.replace("hxxp", "http")
    paragraph = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', paragraph)
    paragraph = re.sub(r'\\u[0-9a-fA-F]{4}', '', paragraph)
    paragraph = paragraph.replace("aka ", "")
    paragraph = paragraph.replace("^", "")
    paragraph = paragraph.replace("|", "")
    return paragraph


def parse_response(response_text: str, task: str) -> Any:
    """Parse the model's response text based on the task's expected XML-like tags."""
    if not response_text:
        return "" if task != "T1" else []

    response_clean = response_text.split("---")[0].split("##")[0].strip()
    flags = re.DOTALL | re.IGNORECASE

    if task == 'T1':
        # Expected: <entities>Ent1|Ent2|...|Entn</entities>
        match = re.search(r'<entities>(.*?)</entities>', response_clean, flags)
        if match:
            content = match.group(1).strip()
            return list(set([entity.strip() for entity in content.split('|') if entity.strip()]))
        logging.warning(f"T1 parsing failed for response snippet: {response_clean[:100]}...")
        return []

    elif task == 'T2':
        # Expected: <entity_type>STIX_ENTITY_TYPE</entity_type>
        match = re.search(r'<entity_type>(.*?)</entity_type>', response_clean, flags)
        if match:
            return match.group(1).strip()
        logging.warning(f"T2 parsing failed for response snippet: {response_clean[:100]}...")
        return ""

    elif task == 'T3':
        # Expected: <related>YES or NO</related>
        match = re.search(r'<related>(.*?)</related>', response_clean, flags)
        if match:
            result = match.group(1).strip().upper()
            return result if result in ["YES", "NO"] else ""
        logging.warning(f"T3 parsing failed for response snippet: {response_clean[:100]}...")
        return ""

    elif task == 'T4':
        # Expected: <label>Your chosen label</label>
        match = re.search(r'<label>(.*?)</label>', response_clean, flags)
        if match:
            return match.group(1).strip()
        logging.warning(f"T4 parsing failed for response snippet: {response_clean[:100]}...")
        return ""

    return response_clean

def get_iocs(text: str) -> Dict[str, List[str]]:
    """Extracts various IOC types using ioc_finder and iocparser."""
    iocs = defaultdict(list)

    try:
        raw_iocs = find_iocs(text)
        iocs['URL'].extend(raw_iocs.get('urls', []))
        iocs['EMAIL'].extend(raw_iocs.get('email_addresses', []))
        iocs['DOMAIN'].extend(raw_iocs.get('domains', []))
        iocs['IPv4'].extend(raw_iocs.get('ipv4s', []))
        iocs['IPv6'].extend(raw_iocs.get('ipv6s', []))
        iocs['FILE_HASH_SHA256'].extend(raw_iocs.get('sha256s', []))
        iocs['FILE_HASH_SHA1'].extend(raw_iocs.get('sha1s', []))
        iocs['FILE_HASH_MD5'].extend(raw_iocs.get('md5s', []))
        iocs['ASN'].extend(raw_iocs.get('asns', []))
        iocs['REGISTRY_KEY'].extend(raw_iocs.get('registry_key_paths', []))
        iocs['MAC_ADDRESS'].extend(raw_iocs.get('mac_addresses', []))
        iocs['FILE_PATH'].extend(raw_iocs.get('file_paths', []))
        for source, tactics in raw_iocs.get('attack_tactics', {}).items():
            iocs['MITRE_ATT&CK'].extend(tactics)
        for source, techniques in raw_iocs.get('attack_techniques', {}).items():
            iocs['MITRE_ATT&CK'].extend(techniques)
    except Exception as e:
        logging.error(f"Error during ioc_finder processing: {e}")

    try:
        text_obj = IOCParser(text)
        results = text_obj.parse()
        for result in results:
            if result.kind == "filename":
                iocs['FILE_NAME'].append(result.value)
    except Exception as e:
        logging.error(f"Error during iocparser processing: {e}")

    try:
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        iocs['CVE'].extend(re.findall(cve_pattern, text, re.IGNORECASE))
        threat_actor_pattern = r'UNC[0-9]{4}|UAC-[0-9]{4}|\bTA\d{3}\b|APT[0-9]{1,2}'
        iocs['THREAT_ACTOR'].extend(re.findall(threat_actor_pattern, text))
    except Exception as e:
        logging.error(f"Error during custom regex matching: {e}")

    final_iocs = {}
    for key, values in iocs.items():
        final_iocs[key] = list(set(values))
    return final_iocs

def get_iocs_set(text: str) -> set:
    """Returns a flat set of all unique IOC strings found in the text."""
    iocs_dict = get_iocs(text=text)
    set_iocs = set()
    for key in iocs_dict.keys():
        for element in iocs_dict[key]:
            set_iocs.add(str(element))
    return set_iocs

def load_dataset(file_path: str) -> List[Dict[str, Any]]:
    """Loads dataset from a JSON file."""
    logging.info(f"Loading dataset from {file_path}...")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("Input JSON format error: expected a list of objects.")
        logging.info(f"Successfully loaded {len(data)} examples.")
        return data
    except FileNotFoundError:
        logging.error(f"Dataset file not found: {file_path}")
        return []
    except Exception as e:
        logging.error(f"Error loading dataset: {e}")
        return []

def run_inference(client: OpenAI, data: List[Dict[str, Any]], task: str, model_name: str) -> List[Dict[str, Any]]:
    """Runs inference on the dataset and parses responses."""
    results = []
    params = TASK_PARAMETERS.get(task, {})
    
    for item in tqdm(data, desc=f"Processing Task {task}"):
        instruction = item.get("instruction", "")
        input_text = item.get("input", "")
        gold_output = item.get("output", "") # Ground truth

        # Clean input before sending to model
        cleaned_input = clean_paragraph(input_text)
        
        # Format prompt
        prompt = f"Instruction: {instruction}\n\nInput: {cleaned_input}\n\nResponse:"

        api_params = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": params.get("temperature", 0.7),
            "max_tokens": params.get("max_tokens", 512),
            "top_p": params.get("top_p", 0.95),
        }

        try:
            response = client.chat.completions.create(**api_params)
            raw_prediction = response.choices[0].message.content or ""
        except Exception as e:
            logging.warning(f"API call failed for input hash {hash(input_text)}: {e}")
            raw_prediction = ""

        parsed_prediction = parse_response(raw_prediction, task)

        results.append({
            "instruction": instruction,
            "input": cleaned_input,
            "gold": gold_output,
            "raw_prediction": raw_prediction,
            "predicted": parsed_prediction,
        })
    return results

def post_process_t1_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Applies T1 specific post-processing: IOC enrichment and filtering."""
    logging.info("Applying Task T1 post-processing logic...")
    processed_results = []
    for result in tqdm(results, desc="Post-processing T1"):
        input_text = result["input"]
        
        external_iocs = get_iocs_set(text=input_text)

        gold_list = parse_response(result["gold"], "T1")
        gold_labels = set()
        for item in gold_list:
            if item and item in input_text:
                gold_labels.add(item)

        predicted_labels = set()
        for item in result["predicted"]:
            if item and item in input_text:
                predicted_labels.add(item)

        final_gold_set = gold_labels.union(external_iocs)
        final_predicted_set = predicted_labels.union(external_iocs)

        result["gold"] = list(final_gold_set)
        result["predicted"] = list(final_predicted_set)
        processed_results.append(result)
        
    return processed_results

def save_results(results: List[Dict[str, Any]], task: str, dataset_name: str, model_name: str):
    """Saves results to a JSON file."""
    sanitized_model_name = re.sub(r'[\\/]', '_', model_name)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"./results/{task}"
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{dataset_name}__{task}__{sanitized_model_name}__{timestamp}.json"
    output_path = os.path.join(output_dir, filename)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    logging.info(f"Results saved successfully to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Run inference using OpenAI API for specified tasks.")
    parser.add_argument("--task", type=str, required=True, choices=["T1", "T2", "T3", "T4"], help="Task identifier.")
    parser.add_argument("--dataset", type=str, required=True, choices=["azerg", "annoctr"], help="Dataset name prefix.")
    parser.add_argument("--model_name", type=str, default="QCRI/AZERG-MixTask-Mistral", help="Name of the model to use.")
    parser.add_argument("--api_key", type=str, default="dummy", help="OpenAI API key.")
    parser.add_argument("--base_url", type=str, default="http://localhost:3216/v1", help="Optional base URL for custom endpoints (e.g., vLLM).")
    args = parser.parse_args()

    # Load data
    dataset_path = f"./AZERG-Dataset/test/{args.dataset}_{args.task}_test.json"
    data_to_process = load_dataset(dataset_path)
    if not data_to_process:
        return

    # Initialize client
    client = OpenAI(api_key=args.api_key, base_url=args.base_url)

    # Run inference
    inference_results = run_inference(client, data_to_process, args.task, args.model_name)

    # Apply task-specific post-processing
    if args.task == "T1":
        final_results = post_process_t1_results(inference_results)
    else:
        final_results = inference_results

    # Save results
    save_results(final_results, args.task, args.dataset, args.model_name)

if __name__ == "__main__":
    main()
