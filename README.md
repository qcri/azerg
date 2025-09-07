# AZERG: Automating STIX Entity and Relationship Extraction

**AZERG** is a framework for automatically extracting Structured Threat Information Expression (STIX) entities and relationships from unstructured cyber threat intelligence reports. This tool uses fine-tuned language models to assist security analysts in generating STIX-compatible data, streamlining the threat intelligence lifecycle.

The project is detailed in our paper: [From Text to Actionable Intelligence: Automating STIX Entity and Relationship Extraction](https://arxiv.org/abs/2507.16576).

The models and datasets are available on Hugging Face:
- **Hugging Face Collection:** [QCRI/azerg](https://huggingface.co/collections/QCRI/azerg-687264a76236a362e833d8eb)
- **Dataset:** [QCRI/AZERG-Dataset](https://huggingface.co/datasets/QCRI/AZERG-Dataset)
- **Models:**
    - [QCRI/AZERG-MixTask-Mistral](https://huggingface.co/QCRI/AZERG-MixTask-Mistral)
    - [QCRI/AZERG-T1-Mistral](https://huggingface.co/QCRI/AZERG-T1-Mistral)
    - [QCRI/AZERG-T2-Mistral](https://huggingface.co/QCRI/AZERG-T2-Mistral)
    - [QCRI/AZERG-T3-Mistral](https://huggingface.co/QCRI/AZERG-T3-Mistral)
    - [QCRI/AZERG-T4-Mistral](https://huggingface.co/QCRI/AZERG-T4-Mistral)

## Quickstart

### 1. Download Datasets

First, download the necessary datasets for running inference and evaluation.

```bash
python download_dataset.py
```

### 2. Install Dependencies

Install the required Python libraries from `requirements.txt`.

```bash
pip install -r requirements.txt
```
### 3. Run Inference

Execute the `run_inference.py` script to generate predictions from a model. The script saves results in the `./results/{TASK}` directory.

**Usage**:

```bash
python run_inference.py --task <TASK> --dataset <DATASET> --model_name <MODEL_NAME> --api_key <YOUR_API_KEY>
```

- `<TASK>`: `T1`, `T2`, `T3`, or `T4`.

- `<DATASET>`: `azerg` or `annoctr`.

- `<MODEL_NAME>`: The model to use for inference (e.g., `QCRI/AZERG-MixTask-Mistral` or `gpt-4o`).

- `<YOUR_API_KEY>`: Your OpenAI-compatible API key.

**Example**:

```bash
python run_inference.py --task T1 --dataset azerg --model_name QCRI/AZERG-MixTask-Mistral
```

### 4. Run Evaluation

Use the `evaluate_results.py` script to calculate performance metrics from the generated result files. The script appends a summary to `results.csv`.

**Usage**:

```bash
python evaluate_results.py --task <TASK> --dataset <DATASET>
```

- `<TASK>`: `T1`, `T2`, `T3`, or `T4`.

- `<DATASET>`: `azerg` or `annoctr`.


**Example**:

```
python evaluate_results.py --task T1 --dataset azerg
```

## Citation

If you use AZERG in your research, please cite our paper:

```
@article{lekssays2025azerg,
  title={From Text to Actionable Intelligence: Automating STIX Entity and Relationship Extraction},
  author={Lekssays, Ahmed and Sencar, Husrev Taha and Yu, Ting},
  journal={arXiv preprint arXiv:2507.16576},
  year={2025}
}
```

## Issues

Please report any bugs or feature requests by opening an issue on our GitHub repository: [https://github.com/QCRI/azerg/issues](https://github.com/QCRI/azerg/issues).
