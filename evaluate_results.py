import os
import json
import glob
import argparse
import ast
import re
from collections import Counter, defaultdict
from typing import Dict, List, Any


ALL_LABELS_T2 = ["ATTACK_PATTERN", "CAMPAIGN", "COURSE_OF_ACTION", "IDENTITY", "INDICATOR",
                 "INFRASTRUCTURE", "LOCATION", "MALWARE", "THREAT_ACTOR", "TOOL", "VULNERABILITY"]

def safe_eval(s):
    """Safely evaluate a string representation of a Python literal (e.g., list)."""
    try:
        return ast.literal_eval(s)
    except (ValueError, SyntaxError, TypeError):
        return s if isinstance(s, list) else []

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
        return []

    elif task == 'T2':
        # Expected: <entity_type>STIX_ENTITY_TYPE</entity_type>
        match = re.search(r'<entity_type>(.*?)</entity_type>', response_clean, flags)
        if match:
            return match.group(1).strip()
        return ""

    elif task == 'T3':
        # Expected: <related>YES or NO</related>
        match = re.search(r'<related>(.*?)</related>', response_clean, flags)
        if match:
            result = match.group(1).strip().upper()
            return result if result in ["YES", "NO"] else ""
        return ""

    elif task == 'T4':
        # Expected: <label>Your chosen label</label>
        match = re.search(r'<label>(.*?)</label>', response_clean, flags)
        if match:
            return match.group(1).strip()
        return ""

    return response_clean

def calculate_metrics_t1(data: List[Dict[str, str]], dataset: str) -> Dict[str, float]:
    """Calculates precision, recall, and F1 for Task T1 (Set comparison)."""
    true_positives = 0
    false_positives = 0
    false_negatives = 0

    for item in data:
        gold = set(safe_eval(item['gold']))
        pred = set(safe_eval(item['predicted']))
        
        true_positives += len(gold.intersection(pred))
        false_positives += len(pred - gold)
        false_negatives += len(gold - pred)

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return {
        'precision': precision, 'recall': recall, 'f1': f1,
        'tp': true_positives, 'fp': false_positives, 'fn': false_negatives, 'dataset': dataset
    }

def calculate_metrics_t2(data: List[Dict[str, str]], dataset: str) -> Dict[str, Dict]:
    """Calculates per-class and overall metrics for Task T2 (Single-label classification)."""
    true_positives = Counter()
    false_positives = Counter()
    false_negatives = Counter()

    for item in data:
        gold = parse_response(item['gold'], "T2")
        pred = item['predicted']
        
        if gold == pred:
            true_positives[gold] += 1
        else:
            false_positives[pred] += 1
            false_negatives[gold] += 1

    metrics = {}
    for label in ALL_LABELS_T2:
        tp = true_positives[label]
        fp = false_positives[label]
        fn = false_negatives[label]
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        metrics[label] = {'precision': precision, 'recall': recall, 'f1': f1, 'tp': tp, 'fp': fp, 'fn': fn}
    
    total_tp = sum(true_positives.values())
    total_fp = sum(false_positives.values())
    total_fn = sum(false_negatives.values())
    
    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    overall_f1 = 2 * (overall_precision * overall_recall) / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0
    
    metrics['overall'] = {'precision': overall_precision, 'recall': overall_recall, 'f1': overall_f1, 'dataset': dataset}
    return metrics

def calculate_metrics_t3(data: List[Dict[str, str]], dataset: str) -> Dict[str, float]:
    """Calculates metrics for Task T3 (Binary classification YES/NO). This logic was formerly T5."""
    true_positives = 0
    true_negatives = 0
    false_positives = 0
    false_negatives = 0

    for item in data:
        gold = parse_response(item['gold'], "T3")
        pred = "YES" if "YES" in str(item['predicted']).upper() else "NO"
        
        if gold == 'YES' and pred == 'YES':
            true_positives += 1
        elif gold == 'NO' and pred == 'NO':
            true_negatives += 1
        elif gold == 'NO' and pred == 'YES':
            false_positives += 1
        elif gold == 'YES' and pred == 'NO':
            false_negatives += 1

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (true_positives + true_negatives) / len(data) if len(data) > 0 else 0

    return {
        'precision': precision, 'recall': recall, 'f1': f1, 'accuracy': accuracy,
        'tp': true_positives, 'tn': true_negatives, 'fp': false_positives, 'fn': false_negatives,
        'dataset': dataset
    }

def calculate_metrics_t4(data: List[Dict[str, str]], dataset: str) -> Dict[str, Dict]:
    """Calculates per-class and overall metrics for Task T4 (Relation type classification) with normalization."""
    true_labels = Counter()
    pred_labels = Counter()
    correct_predictions = Counter()
    label_pairs = []

    for item in data:
        gold = parse_response(item['gold'], "T4").replace("is ", "").replace(" ", "-")
        pred = str(item['predicted']).replace("is ", "").replace(" ", "-")
        
        if pred == "use":
            pred = "uses"
        elif gold == "use":
            gold = "uses"

        if pred in ['beacons-to', 'communicates-with', 'exfiltrates-to']:
            pred = "communicates-with"
        if gold in ['beacons-to', 'communicates-with', 'exfiltrates-to']:
            gold = "communicates-with"

        if pred in ['downloads', 'drops']:
            pred = "downloads"
        if gold in ['downloads', 'drops']:
            gold = "downloads"

        label_pairs.append((gold, pred))
        true_labels[gold] += 1
        pred_labels[pred] += 1
        if gold == pred:
            correct_predictions[gold] += 1

    all_labels = set(true_labels.keys()) | set(pred_labels.keys())
    metrics = {}
    
    for label in all_labels:
        tp = correct_predictions[label]
        fp = sum(1 for g, p in label_pairs if p == label and g != label)
        fn = sum(1 for g, p in label_pairs if g == label and p != label)
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        metrics[label] = {'precision': precision, 'recall': recall, 'f1': f1, 'tp': tp, 'fp': fp, 'fn': fn}
    
    total_correct = sum(correct_predictions.values())
    total_predictions = len(data)
    accuracy = total_correct / total_predictions if total_predictions > 0 else 0
    
    metrics['overall'] = {'precision': accuracy, 'recall': accuracy, 'f1': accuracy, 'accuracy': accuracy, 'dataset': dataset}
    return metrics

def load_results(task: str, dataset_filter: str) -> Dict[str, list]:
    """Loads all result files matching task, dataset, and parameter criteria."""
    data = defaultdict(list)
    search_pattern = f"./results/{task}/*.json"
    print(f"Searching for files matching: task={task}, dataset={dataset_filter}")
    
    for file_path in glob.glob(search_pattern):
        filename = os.path.basename(file_path)
        if dataset_filter not in filename:
            continue
            
        try:
            model_name = filename.split('__')[1]
        except IndexError:
            continue

        print(f"Loading data for model '{model_name}' from file: {filename}")
        with open(file_path, "r") as f:
            data[model_name] = json.load(f)
    
    if not data:
        print(f"Warning: No data loaded for specified criteria.")
    return data

def write_csv_results(results: Dict[str, Dict[str, Dict]], 
                     task: str, 
                     dataset: str):
    """Appends model performance metrics to results.csv."""
    output_filename = 'results.csv'
    file_exists = os.path.isfile(output_filename)
    
    with open(output_filename, 'a', newline='') as f:
        if not file_exists:
            f.write("model,dataset,task,precision,recall,f1_score\n")
        
        for model, metrics in results.items():
            if task in ['T1', 'T3']:
                metric_source = metrics
                f1_score = metric_source['f1']
            elif task in ['T2', 'T4']:
                metric_source = metrics['overall']
                f1_score = metric_source['f1']

            f.write(f"{model},{dataset},{task},"
                    f"{metric_source['precision']:.8f},{metric_source['recall']:.8f},{f1_score:.8f}\n")
    print(f"Results appended to {output_filename}")


def main():
    parser = argparse.ArgumentParser(description='Process results for different tasks.')
    parser.add_argument('--task', type=str, choices=['T1', 'T2', 'T3', 'T4'], help='Task to process (T1, T2, T3, T4)')
    parser.add_argument('--dataset', type=str, choices=['annoctr', 'azerg'], help='Dataset configuration to evaluate.')
    args = parser.parse_args()

    dataset = args.dataset

    data = load_results(task=args.task, dataset_filter=dataset)
    if not data:
        return

    results = {}
    if args.task == 'T1':
        results = {model: calculate_metrics_t1(predictions, dataset) for model, predictions in data.items()}
    elif args.task == 'T2':
        results = {model: calculate_metrics_t2(predictions, dataset) for model, predictions in data.items()}
    elif args.task == "T3":
        results = {model: calculate_metrics_t3(predictions, dataset) for model, predictions in data.items()}
    elif args.task == "T4":
        results = {model: calculate_metrics_t4(predictions, dataset) for model, predictions in data.items()}

    write_csv_results(results, args.task, args.dataset)

if __name__ == '__main__':
    main()
