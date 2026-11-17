"""Comment: content modules (parameters 23-28, full implementation)."""

from modules.content.content_modules import (
    OffuscamentoJs,
    FormActionEsterno,
    IframeNascosti,
    LinkEsterniHotlink,
    NlpSemantica,
    ClonazioneVisiva,
)

MODULES: dict[str, type] = {
    "offuscamento_js": OffuscamentoJs,
    "form_action_esterno": FormActionEsterno,
    "iframe_nascosti": IframeNascosti,
    "link_esterni_hotlink": LinkEsterniHotlink,
    "nlp_semantica": NlpSemantica,
    "clonazione_visiva": ClonazioneVisiva,
}

__all__ = [
    "OffuscamentoJs", "FormActionEsterno", "IframeNascosti",
    "LinkEsterniHotlink", "NlpSemantica", "ClonazioneVisiva", "MODULES",
]
