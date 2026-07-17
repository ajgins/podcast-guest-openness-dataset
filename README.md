# Which Podcasts Actually Book Outside Guests? Guest-Openness Scores for 314 Shows

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21310079.svg)](https://doi.org/10.5281/zenodo.21310079)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)

**314 podcasts, scored 0 to 100 on how open they are to booking outside guests**, built
from each show's own public RSS feed and its public Apple Podcasts listing. 14 niches.

Anyone who wants to be a guest on a podcast hits the same wall and has no data to get past it: of
the shows in my niche, which ones actually book outside guests, and which are a host talking alone
or a closed network production? You can answer it by hand, one feed at a time, or you can use this.

## Files

| File | What it is |
| --- | --- |
| [`data.csv`](data.csv) | One row per show, 314 rows. |
| [`data.json`](data.json) | Identical content, plus a `meta` block. |

Both are byte-identical to the distribution the site serves live at
[https://letsmakeapodcast.com/research/which-podcasts-book-guests/data.csv](https://letsmakeapodcast.com/research/which-podcasts-book-guests/data.csv), which is where this repo is generated from.

## Columns

| Column | Type | Meaning |
| --- | --- | --- |
| `slug` | string | Stable id for the show. |
| `show_name` | string | Title as published on Apple Podcasts. |
| `publisher` | string | The feed's stated author. Often a tagline, not a person. |
| `niche` / `niche_name` | string | Which of the 14 niches the show was sampled from. |
| `genre` | string | Apple's own genre label. |
| `episode_count` | int | Episodes in the feed at check time. |
| `cadence` | string | How often it publishes. |
| `last_episode_at` | date | Most recent episode. |
| `active` | bool | Published recently enough to still be running. |
| `publishes_guest_evidence` | bool | The show's own titles or description show it books guests. |
| `network_run` | bool | Published by a network rather than an independent creator. |
| `dormant` | bool | No recent episodes. |
| `openness_score` | 0-100 | The blunt composite. See Method. |
| `feed_checked_at` | datetime | When we read the feed. |
| `apple_url` | url | The public listing. |

⚠️ The column is `publishes_guest_evidence`, never `books_guests`. That distinction is the whole
point of the Limits section below, and it is load bearing.

## Method

For each show we fetched its public RSS feed and read four things the show says about itself:

1. whether recent episode titles or its own description show that it books guests,
2. how long since it last published,
3. how often it publishes,
4. whether the author is an independent creator or a network.

Those four combine into a blunt, public 0 to 100 `openness_score`. Feeds that could not be read
are **excluded from the file** rather than counted as absent evidence.

The same `openness_score` in this file is the score the site's own search ranks on, so any row can
be checked against the show's live feed. There is no private signal.

## What the corpus says

- **259 of 314** shows are still active.
- **99** publish direct evidence that they book guests.
- **71** are dormant, and **66** are network run.
- Feeds checked 2026-07-16.

The per niche breakdown and the write up are at **[https://letsmakeapodcast.com/research/which-podcasts-book-guests](https://letsmakeapodcast.com/research/which-podcasts-book-guests)**.

## Limits, stated plainly

- This measures **whether the door is the kind that opens**. It does not predict whether a given
  host will reply to you. Nothing here is a response rate.
- A show with no guest marker in its recent titles is **not** proven to be guest free. Some
  interview shows credit guests in a format no parser catches, so we count published evidence and
  never its absence.
- The corpus is a **sample** of business, technology, health and adjacent niches, not a census of
  all podcasts. It skews toward established shows on the Apple charts.
- **No contact details of any kind are included**, by design. A dataset of shows is not a mailing
  list, and this file is CC BY.

## Cite it

> Let's Make A Podcast. *Which Podcasts Actually Book Outside Guests? Guest-Openness Scores for 314 Shows*. Zenodo. https://doi.org/10.5281/zenodo.21310079

## License

[CC BY 4.0](LICENSE). Use it, build on it, please cite it.

Maintained by [Let's Make A Podcast](https://letsmakeapodcast.com), which matches podcast hosts with guests. The scored
shows are browsable at [https://letsmakeapodcast.com/podcasts](https://letsmakeapodcast.com/podcasts).
