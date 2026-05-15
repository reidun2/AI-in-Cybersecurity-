from __future__ import annotations

import json
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "work" / "lab2_solution.ipynb"


def lines(text: str) -> list[str]:
    body = textwrap.dedent(text).strip("\n")
    if not body:
        return []
    return [f"{line}\n" for line in body.splitlines()]


def markdown_cell(text: str) -> dict:
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": lines(text),
    }


def code_cell(text: str) -> dict:
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": lines(text),
    }


cells = [
    markdown_cell(
        """
        # Lab 2: Basic Anomaly Detection for Cybersecurity Logs

        This notebook implements a small end-to-end anomaly detection workflow for synthetic authentication logs.

        The simulated attack patterns are aligned with:
        - **MITRE ATT&CK T1110 - Brute Force**
        - **MITRE ATT&CK T1078 - Valid Accounts**

        The final pipeline includes:
        - synthetic dataset generation,
        - exploratory data analysis,
        - anomaly detection with **Isolation Forest**,
        - 2D visualization with **PCA**.
        """
    ),
    code_cell(
        """
        import numpy as np
        import pandas as pd
        import seaborn as sns
        import matplotlib.pyplot as plt

        from sklearn.compose import ColumnTransformer
        from sklearn.decomposition import PCA
        from sklearn.ensemble import IsolationForest
        from sklearn.metrics import accuracy_score, precision_score, recall_score
        from sklearn.preprocessing import OneHotEncoder, StandardScaler

        try:
            from IPython.display import display
        except ImportError:
            def display(value):
                print(value)

        sns.set_theme(style="whitegrid", context="talk")
        plt.rcParams["figure.figsize"] = (12, 6)

        RANDOM_SEED = 42
        rng = np.random.default_rng(RANDOM_SEED)
        """
    ),
    markdown_cell(
        """
        ## 1. Prepare a Cybersecurity-Related Dataset

        The dataset models employee authentication events collected from VPN, SSH, and web portal access logs.
        Most events represent normal employee behavior during business hours.
        A small minority of events simulate:
        - repeated failed login bursts typical for brute-force activity,
        - suspicious successful logins from unusual locations and devices that resemble valid-account abuse.
        """
    ),
    code_cell(
        """
        users = [
            "alice", "bob", "carol", "dave", "erin", "frank",
            "grace", "heidi", "ivan", "judy", "mallory", "oscar"
        ]
        user_weights = np.array([0.12, 0.11, 0.09, 0.08, 0.08, 0.08, 0.1, 0.09, 0.08, 0.07, 0.05, 0.05])
        user_weights = user_weights / user_weights.sum()

        expected_countries = {
            "alice": ["Israel", "Germany"],
            "bob": ["Israel", "United Kingdom"],
            "carol": ["Germany", "Netherlands"],
            "dave": ["Germany", "Poland"],
            "erin": ["United Kingdom", "France"],
            "frank": ["United Kingdom", "Spain"],
            "grace": ["United States", "Canada"],
            "heidi": ["United States", "Canada"],
            "ivan": ["Poland", "Germany"],
            "judy": ["Poland", "Romania"],
            "mallory": ["France", "Belgium"],
            "oscar": ["France", "Spain"],
        }
        rare_countries = ["Brazil", "Nigeria", "Russia", "Vietnam", "Turkey", "Singapore"]
        privileged_users = ["alice", "bob", "grace", "heidi"]

        weekday_offsets = [offset for offset in range(28) if (pd.Timestamp("2026-02-01") + pd.Timedelta(days=offset)).dayofweek < 5]
        weekend_offsets = [offset for offset in range(28) if (pd.Timestamp("2026-02-01") + pd.Timedelta(days=offset)).dayofweek >= 5]
        start_date = pd.Timestamp("2026-02-01")


        def sample_day(prefer_weekend=False):
            if prefer_weekend and rng.random() < 0.6:
                return start_date + pd.Timedelta(days=int(rng.choice(weekend_offsets)))
            if not prefer_weekend and rng.random() < 0.82:
                return start_date + pd.Timedelta(days=int(rng.choice(weekday_offsets)))
            return start_date + pd.Timedelta(days=int(rng.integers(0, 28)))


        def sample_timestamp(normal=True):
            day = sample_day(prefer_weekend=not normal)
            if normal:
                hour = int(np.clip(rng.normal(13, 2.5), 6, 21))
            else:
                if rng.random() < 0.75:
                    hour = int(rng.choice([0, 1, 2, 3, 4, 22, 23]))
                else:
                    hour = int(rng.integers(0, 24))
            minute = int(rng.integers(0, 60))
            second = int(rng.integers(0, 60))
            return day + pd.Timedelta(hours=hour, minutes=minute, seconds=second)


        def generate_normal_event():
            user = rng.choice(users, p=user_weights)
            timestamp = sample_timestamp(normal=True)
            protocol = rng.choice(["vpn", "web_portal", "ssh"], p=[0.45, 0.4, 0.15])
            device_type = rng.choice(["managed_laptop", "desktop", "mobile"], p=[0.68, 0.2, 0.12])
            source_country = rng.choice(expected_countries[user], p=[0.87, 0.13])

            failed_attempts_1h = int(np.clip(np.rint(rng.normal(0.7, 0.9)), 0, 4))
            login_attempts_10m = int(np.clip(failed_attempts_1h + 1 + rng.integers(0, 2), 1, 5))
            session_duration_sec = int(np.clip(rng.gamma(shape=3.2, scale=700), 180, 14400))
            bytes_sent = int(np.clip(rng.lognormal(mean=9.5, sigma=0.5), 2_000, 300_000))
            bytes_received = int(np.clip(rng.lognormal(mean=10.2, sigma=0.55), 3_000, 500_000))

            return {
                "timestamp": timestamp,
                "user": user,
                "source_country": source_country,
                "protocol": protocol,
                "device_type": device_type,
                "failed_attempts_1h": failed_attempts_1h,
                "login_attempts_10m": login_attempts_10m,
                "session_duration_sec": session_duration_sec,
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_received,
                "attack_type": "normal",
                "is_attack": 0,
            }


        def generate_brute_force_event():
            user = rng.choice(privileged_users, p=[0.35, 0.25, 0.2, 0.2])
            timestamp = sample_timestamp(normal=False)
            protocol = rng.choice(["ssh", "web_portal"], p=[0.8, 0.2])
            source_country = rng.choice(rare_countries)

            failed_attempts_1h = int(rng.integers(12, 36))
            login_attempts_10m = int(rng.integers(failed_attempts_1h, failed_attempts_1h + 12))
            session_duration_sec = int(rng.integers(10, 240))
            bytes_sent = int(rng.integers(200, 4_000))
            bytes_received = int(rng.integers(300, 6_000))

            return {
                "timestamp": timestamp,
                "user": user,
                "source_country": source_country,
                "protocol": protocol,
                "device_type": "unknown_host",
                "failed_attempts_1h": failed_attempts_1h,
                "login_attempts_10m": login_attempts_10m,
                "session_duration_sec": session_duration_sec,
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_received,
                "attack_type": "brute_force",
                "is_attack": 1,
            }


        def generate_valid_account_abuse_event():
            user = rng.choice(privileged_users, p=[0.3, 0.25, 0.25, 0.2])
            timestamp = sample_timestamp(normal=False)
            source_country = rng.choice(rare_countries)
            protocol = rng.choice(["vpn", "web_portal"], p=[0.75, 0.25])

            failed_attempts_1h = int(rng.integers(0, 3))
            login_attempts_10m = int(rng.integers(1, 4))
            session_duration_sec = int(rng.integers(4_000, 20_000))
            bytes_sent = int(np.clip(rng.lognormal(mean=12.2, sigma=0.45), 200_000, 3_500_000))
            bytes_received = int(np.clip(rng.lognormal(mean=12.5, sigma=0.45), 250_000, 5_000_000))

            return {
                "timestamp": timestamp,
                "user": user,
                "source_country": source_country,
                "protocol": protocol,
                "device_type": "new_device",
                "failed_attempts_1h": failed_attempts_1h,
                "login_attempts_10m": login_attempts_10m,
                "session_duration_sec": session_duration_sec,
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_received,
                "attack_type": "valid_account_abuse",
                "is_attack": 1,
            }


        normal_events = [generate_normal_event() for _ in range(4_850)]
        brute_force_events = [generate_brute_force_event() for _ in range(100)]
        valid_account_events = [generate_valid_account_abuse_event() for _ in range(50)]

        df = pd.DataFrame(normal_events + brute_force_events + valid_account_events)
        df = df.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
        df["hour"] = df["timestamp"].dt.hour
        df["day_name"] = df["timestamp"].dt.day_name()

        print(f"Dataset shape: {df.shape}")
        print(f"Attack ratio: {df['is_attack'].mean():.2%}")
        display(df.head())
        """
    ),
    code_cell(
        """
        class_distribution = df["attack_type"].value_counts().rename_axis("attack_type").reset_index(name="count")
        display(class_distribution)

        print("Anomalies are a small minority, which is appropriate for Isolation Forest.")
        """
    ),
    markdown_cell(
        """
        ## 2. Exploratory Data Analysis (EDA)
        """
    ),
    code_cell(
        """
        num_rows, num_features = df.shape
        print(f"Number of rows: {num_rows}")
        print(f"Number of features: {num_features}")
        print("\\nClass distribution:")
        print(df["attack_type"].value_counts())
        print("\\nMissing values per column:")
        print(df.isna().sum())
        """
    ),
    code_cell(
        """
        fig, axes = plt.subplots(2, 2, figsize=(18, 12))

        sns.histplot(data=df, x="failed_attempts_1h", hue="is_attack", bins=25, multiple="stack", ax=axes[0, 0])
        axes[0, 0].set_title("Failed Attempts in the Last Hour")
        axes[0, 0].set_xlabel("failed_attempts_1h")

        top_countries = df["source_country"].value_counts().head(8).index
        sns.countplot(
            data=df[df["source_country"].isin(top_countries)],
            x="source_country",
            hue="is_attack",
            order=top_countries,
            ax=axes[0, 1],
        )
        axes[0, 1].set_title("Top Source Countries")
        axes[0, 1].tick_params(axis="x", rotation=30)

        hourly_counts = df.groupby(["hour", "is_attack"]).size().reset_index(name="count")
        sns.lineplot(data=hourly_counts, x="hour", y="count", hue="is_attack", marker="o", ax=axes[1, 0])
        axes[1, 0].set_title("Authentication Events by Hour")
        axes[1, 0].set_xticks(range(0, 24, 2))

        sample = df.sample(2_000, random_state=RANDOM_SEED)
        sns.scatterplot(
            data=sample,
            x="session_duration_sec",
            y="bytes_sent",
            hue="is_attack",
            alpha=0.7,
            ax=axes[1, 1],
        )
        axes[1, 1].set_title("Session Duration vs Bytes Sent")
        axes[1, 1].set_xlabel("session_duration_sec")
        axes[1, 1].set_ylabel("bytes_sent")

        plt.tight_layout()
        plt.show()
        """
    ),
    markdown_cell(
        """
        ### Analytical Summary

        Normal authentication activity is concentrated around business hours and comes mostly from each user's expected country set.
        Most benign sessions contain very few failed attempts, short login bursts, and moderate traffic volumes.
        The two synthetic anomaly families break those patterns in different ways: brute-force events create many failed attempts in short time windows, while valid-account abuse looks more subtle and is driven by unusual locations, devices, and very large sessions.
        Based on these patterns, we expect Isolation Forest to detect the night-time login bursts easily and to flag at least part of the unusual successful sessions as outliers near the edges of the feature space.
        """
    ),
    markdown_cell(
        """
        ## 3. Apply an Anomaly Detection Model

        The primary model required by the assignment is **Isolation Forest**.
        We will preprocess the mixed feature set by:
        - scaling numeric features,
        - one-hot encoding categorical features,
        - fitting the detector on the full dataset with the true anomaly ratio used as the contamination level.
        """
    ),
    code_cell(
        """
        numeric_features = [
            "hour",
            "failed_attempts_1h",
            "login_attempts_10m",
            "session_duration_sec",
            "bytes_sent",
            "bytes_received",
        ]
        categorical_features = ["user", "source_country", "protocol", "device_type", "day_name"]

        X_raw = df[numeric_features + categorical_features]
        y_true = df["is_attack"].to_numpy()

        preprocessor = ColumnTransformer(
            transformers=[
                ("num", StandardScaler(), numeric_features),
                ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
            ],
            sparse_threshold=0,
        )

        X_processed = preprocessor.fit_transform(X_raw)
        if hasattr(X_processed, "toarray"):
            X_processed = X_processed.toarray()
        X_processed = np.asarray(X_processed, dtype=float)

        model = IsolationForest(
            n_estimators=300,
            contamination=float(y_true.mean()),
            random_state=RANDOM_SEED,
        )
        model.fit(X_processed)

        df["anomaly_score"] = -model.decision_function(X_processed)
        df["iforest_pred"] = (model.predict(X_processed) == -1).astype(int)
        df["predicted_label"] = np.where(df["iforest_pred"] == 1, "anomalous", "normal")

        display(
            df[[
                "timestamp",
                "user",
                "source_country",
                "protocol",
                "failed_attempts_1h",
                "session_duration_sec",
                "attack_type",
                "predicted_label",
                "anomaly_score",
            ]].head()
        )
        """
    ),
    code_cell(
        """
        metrics_table = pd.DataFrame(
            {
                "metric": ["accuracy", "precision", "recall"],
                "value": [
                    accuracy_score(y_true, df["iforest_pred"]),
                    precision_score(y_true, df["iforest_pred"], zero_division=0),
                    recall_score(y_true, df["iforest_pred"], zero_division=0),
                ],
            }
        )

        detected_anomalies = int(df["iforest_pred"].sum())
        print(f"Isolation Forest detected {detected_anomalies} anomalies out of {len(df)} events.")
        print("\\nConfusion table:")
        print(pd.crosstab(df["attack_type"], df["predicted_label"]))
        print("\\nMetrics:")
        display(metrics_table)

        plt.figure(figsize=(12, 6))
        sns.histplot(data=df, x="anomaly_score", hue="attack_type", bins=40, multiple="stack")
        plt.title("Distribution of Isolation Forest Anomaly Scores")
        plt.xlabel("anomaly_score (higher means more suspicious)")
        plt.show()

        print("Top 10 most suspicious events:")
        display(
            df.nlargest(10, "anomaly_score")[
                [
                    "timestamp",
                    "user",
                    "source_country",
                    "protocol",
                    "device_type",
                    "failed_attempts_1h",
                    "login_attempts_10m",
                    "session_duration_sec",
                    "bytes_sent",
                    "attack_type",
                    "anomaly_score",
                ]
            ]
        )
        """
    ),
    markdown_cell(
        """
        ## 4. Visualize Anomalies on a 2D Projection

        We use **PCA** as the baseline dimensionality-reduction method.
        The projection is computed from the same preprocessed feature matrix that was used by Isolation Forest.
        """
    ),
    code_cell(
        """
        pca = PCA(n_components=2)
        projection = pca.fit_transform(X_processed)

        df["pca_1"] = projection[:, 0]
        df["pca_2"] = projection[:, 1]

        fig, axes = plt.subplots(1, 2, figsize=(18, 7), sharex=True, sharey=True)

        sns.scatterplot(
            data=df,
            x="pca_1",
            y="pca_2",
            hue="attack_type",
            alpha=0.7,
            s=45,
            ax=axes[0],
        )
        axes[0].set_title("Ground Truth Labels in PCA Space")

        sns.scatterplot(
            data=df,
            x="pca_1",
            y="pca_2",
            hue="predicted_label",
            alpha=0.7,
            s=45,
            ax=axes[1],
        )
        axes[1].set_title("Isolation Forest Predictions in PCA Space")

        plt.tight_layout()
        plt.show()

        explained_variance = pca.explained_variance_ratio_.sum()
        print(f"Explained variance captured by the first two PCA components: {explained_variance:.2%}")
        """
    ),
    markdown_cell(
        """
        ### 2D Projection Interpretation

        The PCA view shows a dense region of normal employee activity surrounded by a smaller number of isolated points and sparse groups.
        The brute-force events are expected to sit far away from the central cluster because their failure counts and login burst intensity are extreme.
        The valid-account-abuse events can overlap more with normal traffic, but many still move toward the edges of the projection due to unusual countries, new devices, and very large session volumes.
        """
    ),
    markdown_cell(
        """
        ## Conclusion

        This notebook demonstrates a complete anomaly detection workflow for cybersecurity logs.
        The synthetic data preserves a realistic imbalance between normal and suspicious events, the EDA highlights the dominant normal behavior, and Isolation Forest identifies outliers without relying on the labels during fitting.
        In practice, the strongest signals come from failed-login bursts, off-hours activity, unusual geolocation patterns, and large sessions from new devices.
        """
    ),
]


notebook = {
    "cells": cells,
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3 (ipykernel)",
            "language": "python",
            "name": "python3",
        },
        "language_info": {
            "codemirror_mode": {"name": "ipython", "version": 3},
            "file_extension": ".py",
            "mimetype": "text/x-python",
            "name": "python",
            "nbconvert_exporter": "python",
            "pygments_lexer": "ipython3",
            "version": "3.13.9",
        },
    },
    "nbformat": 4,
    "nbformat_minor": 5,
}


OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with OUTPUT.open("w", encoding="utf-8") as fh:
    json.dump(notebook, fh, indent=1, ensure_ascii=False)
    fh.write("\n")

print(f"Wrote notebook to {OUTPUT}")
