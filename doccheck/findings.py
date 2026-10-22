"""Achado (finding): uma divergência ou observação, com severidade, explicação e ação sugerida."""
from __future__ import annotations

from dataclasses import asdict, dataclass

SEV_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 0}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_LABEL = {"critical": "Crítico", "high": "Alto", "medium": "Médio", "low": "Baixo", "info": "Info"}

# O que a pessoa que confere o documento deve fazer em cada caso.
ACTIONS = {
    "cpf_invalido": "Confira o CPF com o cliente e na Receita Federal. Não prossiga com um CPF inválido.",
    "cpf_diverge": "Documentos com CPFs diferentes não pertencem à mesma pessoa. Peça os documentos corretos e escale para a revisão.",
    "nascimento_diverge": "Confirme a data de nascimento com um documento oficial e escale para a revisão.",
    "nome_diverge": "Verifique se é a mesma pessoa. Se o documento está em nome de terceiro, peça comprovante de vínculo.",
    "nome_similar": "Provável diferença de grafia (acento, abreviação). Confirme com o cliente.",
    "cnh_vencida": "Peça a CNH vigente ou outro documento oficial com foto.",
    "datas_incoerentes": "As datas do documento não fazem sentido entre si. Peça um novo documento e escale.",
    "cnh_numero": "Confirme o número de registro olhando a CNH. Para validar a CNH de verdade, use o QR Code da Carteira Digital de Trânsito ou o Detran.",
    "cnpj_invalido": "Confirme o CNPJ do empregador na Receita Federal.",
    "conta_nao_fecha": "O holerite não bate: bruto menos descontos deveria ser igual ao líquido. Peça o documento direto do empregador.",
    "renda_acima": "A renda declarada é maior que a renda comprovada. Peça comprovação adicional.",
    "comprovante_antigo": "Peça um comprovante mais recente, dentro do prazo da política.",
    "data_futura": "A data do documento está no futuro. Peça outro documento e escale.",
    "editor_detectado": "Peça o arquivo original, baixado direto do emissor (banco, empresa, concessionária), e compare.",
    "modificado_apos_criacao": "Peça o arquivo original, baixado direto do emissor.",
    "atualizacao_incremental": "O PDF foi alterado depois de gerado. Peça o original do emissor.",
    "conteudo_ativo": "Não abra este arquivo em um leitor comum. Envie para a equipe de segurança.",
    "arquivo_criado_antes": "O arquivo existe antes da data em que o documento diz ter sido emitido. Escale para a revisão.",
    "arquivo_duplicado": "O mesmo arquivo foi enviado como dois documentos diferentes. Peça os documentos corretos.",
    "sem_metadados": "Comum em prints e imagens reenviadas. Peça o PDF original do emissor.",
    "cep_diverge": "Confirme o endereço com o cliente.",
}


@dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str = ""
    doc: str = "geral"
    action: str = ""

    def __post_init__(self):
        if not self.action:
            self.action = ACTIONS.get(self.code, "")

    @property
    def weight(self) -> int:
        return SEV_WEIGHT[self.severity]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["weight"] = self.weight
        return d
