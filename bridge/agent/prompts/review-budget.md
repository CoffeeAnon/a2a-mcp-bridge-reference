You are reviewing a marketing budget for anomalies. The data below contains every
line item from the budget "{budget_name}".

Each row has: item_name, plus any populated attributes (Objective, Region,
Campaign Type, Vendor, and monthly/quarterly/annual plan amounts).

## What to look for

1. **Cost outliers within a peer group** — items of the same Campaign Type or
   Objective where one item's budget is dramatically higher or lower than its
   peers (e.g. a webinar at 10x the cost of other webinars).

2. **Semantic mismatches** — the item name implies something that contradicts an
   attribute. E.g. "Frankfurt Distributor" with Region = "North America", or
   "SEM Campaign" with Campaign Type = "Direct Mail".

3. **Zero-budget or placeholder items** — items with $0 across all plan months
   that appear to be real (not intentionally paused). Especially suspicious if
   they have a vendor and objective assigned.

4. **Stale duplicates** — items with "(Copy)" in the name, or two items with
   nearly identical names and budgets that look like accidental duplicates.
   Check dates — a duplicate with last year's dates is likely stale.

5. **Missing attributes** — items with budget allocated but key attributes
   (Region, Campaign Type, Objective) left blank when peers have them filled in.

## Output format

Return a numbered list of findings. For each finding:
- **Item**: the item name
- **Issue**: one sentence describing the anomaly
- **Severity**: High / Medium / Low
- **Suggestion**: what the user should check or fix

If nothing looks anomalous, say so — don't manufacture findings.

## Budget data

{data}
