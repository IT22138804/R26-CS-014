from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelEncoder, RobustScaler, StandardScaler

from .labels import expected_control_label
from .spectral import engineer_trigger_centric_features


@dataclass
class ActivationClusterModel:
    feature_scaler: RobustScaler
    classifier: MLPClassifier
    activation_scaler: StandardScaler
    pca: PCA
    kmeans: KMeans
    suspicious_cluster: int
    cluster_summary: list[dict[str, Any]]
    target_observed_label: str


def extract_hidden_activations(
    classifier: MLPClassifier,
    scaled_features: np.ndarray,
) -> np.ndarray:
    """Return the final hidden-layer activations of an sklearn MLP."""
    activations = np.asarray(scaled_features, dtype=float)

    for weights, bias in zip(
        classifier.coefs_[:-1],
        classifier.intercepts_[:-1],
        strict=True,
    ):
        activations = activations @ weights + bias

        if classifier.activation == "relu":
            activations = np.maximum(activations, 0.0)
        elif classifier.activation == "tanh":
            activations = np.tanh(activations)
        elif classifier.activation == "logistic":
            activations = 1.0 / (
                1.0 + np.exp(-activations)
            )
        elif classifier.activation == "identity":
            pass
        else:
            raise ValueError(
                f"Unsupported activation: {classifier.activation}"
            )

    return activations


def policy_mismatch_mask(frame: pd.DataFrame) -> np.ndarray:
    expected = np.asarray(
        [
            expected_control_label(
                float(temperature),
                float(soil),
            )
            for temperature, soil in zip(
                frame["temperature_c"],
                frame["soil_pct"],
                strict=True,
            )
        ],
        dtype=object,
    )

    observed = frame["control_label_observed"].astype(str).to_numpy()
    return expected != observed


def fit_activation_cluster_model(
    training_frame: pd.DataFrame,
    *,
    target_observed_label: str = "NORMAL",
    random_state: int = 39031,
    pca_components: int = 8,
) -> ActivationClusterModel:
    engineered = engineer_trigger_centric_features(training_frame)

    feature_scaler = RobustScaler(
        quantile_range=(10.0, 90.0),
    )
    scaled_features = feature_scaler.fit_transform(engineered)

    classifier = MLPClassifier(
        hidden_layer_sizes=(32, 16),
        activation="relu",
        solver="adam",
        alpha=1e-4,
        learning_rate_init=1e-3,
        max_iter=500,
        early_stopping=True,
        validation_fraction=0.10,
        n_iter_no_change=20,
        random_state=random_state,
    )
    label_encoder = LabelEncoder()
    encoded_labels = label_encoder.fit_transform(
        training_frame["control_label_observed"].astype(str)
    )

    classifier.fit(
        scaled_features,
        encoded_labels,
    )

    hidden = extract_hidden_activations(
        classifier,
        scaled_features,
    )

    target_mask = (
        training_frame["control_label_observed"].astype(str)
        == target_observed_label
    ).to_numpy()

    target_hidden = hidden[target_mask]
    target_frame = training_frame.loc[target_mask].copy()

    if len(target_frame) < 200:
        raise ValueError(
            "Activation clustering requires at least 200 target-label rows."
        )

    activation_scaler = StandardScaler()
    standardized = activation_scaler.fit_transform(target_hidden)

    component_count = min(
        pca_components,
        standardized.shape[1],
    )
    pca = PCA(
        n_components=component_count,
        random_state=random_state,
    )
    embedded = pca.fit_transform(standardized)

    kmeans = KMeans(
        n_clusters=2,
        n_init=25,
        random_state=random_state,
    )
    cluster_ids = kmeans.fit_predict(embedded)

    mismatch = policy_mismatch_mask(target_frame)
    global_center = np.median(embedded, axis=0)

    raw_summaries: list[dict[str, Any]] = []
    maximum_distance = 0.0

    for cluster_id in range(kmeans.n_clusters):
        cluster_mask = cluster_ids == cluster_id
        cluster_size = int(cluster_mask.sum())
        size_ratio = cluster_size / len(target_frame)
        mismatch_rate = float(
            mismatch[cluster_mask].mean()
            if cluster_size
            else 0.0
        )

        centroid = kmeans.cluster_centers_[cluster_id]
        centroid_distance = float(
            np.linalg.norm(centroid - global_center)
        )
        maximum_distance = max(
            maximum_distance,
            centroid_distance,
        )

        raw_summaries.append(
            {
                "cluster_id": cluster_id,
                "cluster_size": cluster_size,
                "size_ratio": size_ratio,
                "policy_mismatch_rate": mismatch_rate,
                "centroid_distance": centroid_distance,
            }
        )

    summaries: list[dict[str, Any]] = []
    for summary in raw_summaries:
        distance_score = (
            summary["centroid_distance"] / maximum_distance
            if maximum_distance > 0.0
            else 0.0
        )
        small_cluster_score = 1.0 - summary["size_ratio"]

        # No poison-ground-truth field is used here.
        suspicion_score = (
            0.65 * summary["policy_mismatch_rate"]
            + 0.20 * small_cluster_score
            + 0.15 * distance_score
        )

        summaries.append(
            {
                **summary,
                "distance_score": distance_score,
                "small_cluster_score": small_cluster_score,
                "suspicion_score": suspicion_score,
            }
        )

    suspicious_cluster = int(
        max(
            summaries,
            key=lambda item: item["suspicion_score"],
        )["cluster_id"]
    )

    return ActivationClusterModel(
        feature_scaler=feature_scaler,
        classifier=classifier,
        activation_scaler=activation_scaler,
        pca=pca,
        kmeans=kmeans,
        suspicious_cluster=suspicious_cluster,
        cluster_summary=summaries,
        target_observed_label=target_observed_label,
    )


def transform_activation_space(
    model: ActivationClusterModel,
    frame: pd.DataFrame,
) -> np.ndarray:
    engineered = engineer_trigger_centric_features(frame)
    scaled = model.feature_scaler.transform(engineered)
    hidden = extract_hidden_activations(
        model.classifier,
        scaled,
    )
    standardized = model.activation_scaler.transform(hidden)
    return model.pca.transform(standardized)


def predict_activation_clusters(
    model: ActivationClusterModel,
    frame: pd.DataFrame,
) -> tuple[np.ndarray, np.ndarray]:
    embedded = transform_activation_space(model, frame)
    cluster_ids = model.kmeans.predict(embedded)

    target_mask = (
        frame["control_label_observed"].astype(str)
        == model.target_observed_label
    ).to_numpy()

    suspicious = (
        target_mask
        & (cluster_ids == model.suspicious_cluster)
    )

    return suspicious, cluster_ids
