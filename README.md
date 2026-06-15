# IDA CFG Parser

This project provides a set of scripts to extract and visualize a full program Control Flow Graph (CFG) from an IDA Pro database (.idb or .i64).


## Dependencies

- IDA Pro (9.0+ for standalone extraction) with IDAPYTHON support.
- Python 3.14+
- `idapro` (for standalone extraction)
- `ipysigma`
- `networkx`
- `pandas`
- `matplotlib`
- `pydot` (optional, for DOT export)


## Project Structure

- `src/extract_cfg.py`: IDA Python script to be run inside IDA Pro.
- `src/extract_cfg_standalone.py`: Standalone Python script for direct database extraction.
- `src/visualize_cfg.py`: Python script to prepare CFG data for visualization.
- `pyproject.toml` / `requirements.txt`: Project dependencies (now using `ipysigma`).
- `sample.ipynb`: Jupyter Notebook for interactive visualization with `ipysigma`.

## Usage

### 1. Extract CFG from IDA

If you have IDA Pro 9.0 or later and the `idapro` package installed, you can extract directly from a database file on disk without launching IDA:

1. **Install the `idapro` library**:
   ```bash
   python3 -m pip install idapro
   ```
2. **Configure IDA Pro path**:
   The `idapro` library needs to know where your IDA Pro installation is. You can configure this by editing `~/.idapro/ida-config.json` (created automatically on first run) or by setting the `IDA_INSTALL_DIR` environment variable.
   
   Example `~/.idapro/ida-config.json`:
   ```json
   {
       "Paths": {
           "ida-install-dir": "/Applications/IDA Pro 9.0.app/Contents/MacOS"
       }
   }
   ```
3. **Run the extraction**:
   ```bash
   python3 -m src.extract_cfg_standalone your_database.i64
   ```
*Note: This requires a valid IDA license and the `idapro` package configured.*

This will generate a `your_database_cfg.json` file in the same directory.

### 2. Visualize CFG

Run the visualization script:
```bash
python3 -m src.visualize_cfg your_database_cfg.json
```
