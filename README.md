# Py-WinRef
*This project is a work in progress!*

Why do this? While working through the SANS FOR508 labs, it occurred to me that it would be nice to 1) have a tool assist with investigating AutoRuns entries, and 2) familiarise myself with the famously performant SQLite, by:

1. Baselining files by hash against Andrew Rathbun's excellent [Vanilla Windows Reference](https://github.com/AndrewRathbun/VanillaWindowsReference),
2. Indexing the National Software Reference Library [Reference Data Set (RDS)](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/about-nsrl), a large collection of hashes for known files, and,
3. Flagging drivers that are in the [LOLDrivers database](https://www.loldrivers.io),
4. Flagging files that are in the [LOLBAS database](https://lolbas-project.github.io).

Why not use one of the many RDS query tools? If you're looking up a large number of rows in an AutoRuns export, or more than one export, it can quickly become a bit time-consuming. Meanwhile, SQLite is shockingly fast, and local lookups (on your device or network) are private.

# How do I use it?
Note: this is a Windows program! Please read this entire README before proceeding, and especially the two large paragraphs below concerning storage requirements.

- Clone the repo, then install these required packages via pip (also, ensure you have Git installed):

`pip install requests gitpython pandas`

- Run lookup.py, which will clone the VanillaWindowsReference (this is currently 16GB+) and LOLDrivers (800MB+) repo, then download the LOLBAS.csv file via the API. You'll also want to separately download the NSRL RDS full SQL (minimal) database from https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download/current-rds and unzip into the same directory as the scripts. When unzipped, it'll exceed 160GB on disk (at the time of this writing, SEP2024). After we index the hash columns to improve lookup speed, this will add another 60GB+ to the database file size.

- Next, you'll need an exported AutoRuns CSV. You can try the included 'autoruns-sus.csv' for a test run.
- Then run db.py for the first time. The first run creates SQL indices for the NSRL file hash columns, and this could take anywhere from 15 minutes to several hours to run, depending on your system. For example (it isn't necessary to specify the path for the LOLDrivers csv, it is populated by default in conf.ini on first run):

`python db.py --autoruns_path autoruns-sus.csv --rds_path RDS_2024.03.1_modern_minimal.db --vwr_path W11_22H2_Pro_20230321_22621.1413.csv`

- To perform a hash lookup (MD5, SHA1, or SHA256):

`python db.py --hash "<hash>"`

![Screenshot](https://github.com/ksyeung/Py-WinRef/blob/main/hash_lookup.png?raw=true)

- To run the full AutoRuns comparison against LOLDrivers, VanillaWindowsReference, and NSRL RDS (the args are for exported CSVs):

`python db.py --compare_autoruns --autoruns_loldrivers_csv loldrivers_matches.csv --autoruns_not_in_vwr_csv not_in_vwr.csv --autoruns_not_in_file_csv not_in_file.csv`

- You may also make changes to file path references in conf.ini. By default, they'll point to paths within the script's directory, as it is where lookup.py will initially download and write the databases.

Example output (using autoruns-sus.csv):
![Screenshot](https://github.com/ksyeung/Py-WinRef/blob/main/not_in_rds.png?raw=true)
![Screenshot](https://github.com/ksyeung/Py-WinRef/blob/main/not_in_vwr.png?raw=true)
