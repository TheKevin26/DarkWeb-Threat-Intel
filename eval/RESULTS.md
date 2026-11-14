# Classifier evaluation

Method: 98 hand-labelled posts, split 50/50 (stratified). Classifier changes were guided only by the
*dev* half; the numbers below are on the untouched *test* half.

## Held-out test set

**Labelled set:** 46 posts · **accuracy 89%** · macro-F1 0.90

| Category | Precision | Recall | F1 | Posts |
|---|---:|---:|---:|---:|
| Initial access broker | 1.00 | 1.00 | 1.00 | 5 |
| Credential leak | 0.80 | 0.80 | 0.80 | 5 |
| Drugs | 1.00 | 1.00 | 1.00 | 5 |
| Exploits & vulnerabilities | 1.00 | 1.00 | 1.00 | 5 |
| Fraud & carding | 1.00 | 0.60 | 0.75 | 5 |
| Hacking services | 1.00 | 1.00 | 1.00 | 5 |
| Malware | 1.00 | 1.00 | 1.00 | 5 |
| Other | 0.56 | 0.83 | 0.67 | 6 |
| Ransomware / extortion | 1.00 | 0.80 | 0.89 | 5 |

Confusion matrix (rows = true label, columns = predicted):

| true \ pred | access | credent | drugs | exploit | fraud | hacking | malware | other | ransomw |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| access | 5 | · | · | · | · | · | · | · | · |
| credent | · | 4 | · | · | · | · | · | 1 | · |
| drugs | · | · | 5 | · | · | · | · | · | · |
| exploit | · | · | · | 5 | · | · | · | · | · |
| fraud | · | · | · | · | 3 | · | · | 2 | · |
| hacking | · | · | · | · | · | 5 | · | · | · |
| malware | · | · | · | · | · | · | 5 | · | · |
| other | · | 1 | · | · | · | · | · | 5 | · |
| ransomw | · | · | · | · | · | · | · | 1 | 4 |

**Real leak-site pages (collected over Tor), text-only classifier:** 9/33 recognised as ransomware (27%). Leak-site front pages are mostly lists of company names with little extortion vocabulary, so the pipeline labels pages from known leak sites by *source* instead of relying on the text classifier for them.

## Full labelled set (dev + test, for reference)

**Labelled set:** 98 posts · **accuracy 94%** · macro-F1 0.94

| Category | Precision | Recall | F1 | Posts |
|---|---:|---:|---:|---:|
| Initial access broker | 1.00 | 1.00 | 1.00 | 11 |
| Credential leak | 0.91 | 0.91 | 0.91 | 11 |
| Drugs | 1.00 | 1.00 | 1.00 | 10 |
| Exploits & vulnerabilities | 1.00 | 0.91 | 0.95 | 11 |
| Fraud & carding | 1.00 | 0.82 | 0.90 | 11 |
| Hacking services | 1.00 | 1.00 | 1.00 | 10 |
| Malware | 0.92 | 1.00 | 0.96 | 11 |
| Other | 0.73 | 0.92 | 0.81 | 12 |
| Ransomware / extortion | 1.00 | 0.91 | 0.95 | 11 |

Confusion matrix (rows = true label, columns = predicted):

| true \ pred | access | credent | drugs | exploit | fraud | hacking | malware | other | ransomw |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| access | 11 | · | · | · | · | · | · | · | · |
| credent | · | 10 | · | · | · | · | · | 1 | · |
| drugs | · | · | 10 | · | · | · | · | · | · |
| exploit | · | · | · | 10 | · | · | 1 | · | · |
| fraud | · | · | · | · | 9 | · | · | 2 | · |
| hacking | · | · | · | · | · | 10 | · | · | · |
| malware | · | · | · | · | · | · | 11 | · | · |
| other | · | 1 | · | · | · | · | · | 11 | · |
| ransomw | · | · | · | · | · | · | · | 1 | 10 |
