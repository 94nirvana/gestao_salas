"""
Gestor de Salas de Reuniao - Versao Full-Stack & AppSec
========================================================
Script Python para agendamento de reunioes considerando:
  - 10 salas disponiveis
  - Horarios de apresentacao: 09:00-12:00 e 13:30-17:30
  - Detecta e previne conflitos de horario
  - Valida e sanitiza todas as entradas (input validation)
  - Tratamento de erros claro e seguro

Autor: Arquiteto de Software Full-Stack & AppSec
Data: 2024
"""

from datetime import datetime, timedelta
from typing import List, Optional
import json
import re

# ============================================================
# CONFIGURACOES DO SISTEMA
# ============================================================

# Numero total de salas disponiveis para agendamento
NUMERO_SALAS: int = 10

# Horarios validos para apresentacoes (formato HH:MM)
# Manha: das 09:00 as 12:00
# Tarde: das 13:30 as 17:30
HORARIOS_VALIDOS: dict = {
    "manha": {"inicio": "09:00", "fim": "12:00"},
    "tarde": {"inicio": "13:30", "fim": "17:30"},
}

# Timeout maximo para uma reuniao (em minutos) - evita agendamentos absurdos
TEMPO_MAXIMO_REUNIAO: int = 180  # 3 horas

# Arquivo JSON para persistencia dos agendamentos
ARQUIVO_AGENDAMENTOS: str = "agendamentos.json"


# ============================================================
# CLASSE REUNIAO
# ============================================================

class Reuniao:
    """
    Representa uma reuniao agendada em uma sala.
    
    Atributos:
        id (str): Identificador unico da reuniao (UUID-like).
        titulo (str): Nome/descrição da reuniao.
        sala (int): Numero da sala (1-10).
        data (datetime): Data da reuniao.
        hora_inicio (datetime): Hora de inicio (validada contra horarios permitidos).
        hora_fim (datetime): Hora de termino.
        participantes (List[str]): Lista de e-mails dos participantes.
    """
    
    def __init__(
        self,
        titulo: str,
        sala: int,
        data: str,
        hora_inicio: str,
        hora_fim: str,
        participantes: Optional[List[str]] = None,
    ):
        self.id: str = self._gerar_id()
        self.titulo: str = self._sanitizar_texto(titulo)
        self.sala: int = self._validar_sala(sala)
        self.data: datetime = self._validar_data(data)
        self.hora_inicio: datetime = self._validar_hora(hora_inicio, "inicio")
        self.hora_fim: datetime = self._validar_hora(hora_fim, "fim")
        self.participantes: List[str] = self._validar_participantes(participantes or [])

    # --- Metodos privados de validacao e sanitizacao ---

    def _gerar_id(self) -> str:
        """Gera um ID unico baseado no timestamp atual + conteudo da reuniao."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        return f"R{timestamp}"

    def _sanitizar_texto(self, texto: str) -> str:
        """
        Sanitiza o titulo da reuniao removendo caracteres perigosos.
        Previne inyecoes e garante consistencia dos dados.
        """
        # Remove tags HTML eJavascript (XSS prevention)
        texto = re.sub(r"<[^>]*>", "", texto)
        # Remove caracteres de controle
        texto = re.sub(r"[\x00-\x1f\x7f]", "", texto)
        # Limita o tamanho para evitar abusos
        if len(texto) > 100:
            texto = texto[:100]
        return texto.strip()

    def _validar_sala(self, sala: int) -> int:
        """Valida se o numero da sala esta dentro do range permitido (1-10)."""
        if not isinstance(sala, int) or sala < 1 or sala > NUMERO_SALAS:
            raise ValueError(
                f"Sala invalida: {sala}. Deve ser um inteiro entre 1 e {NUMERO_SALAS}."
            )
        return sala

    def _validar_data(self, data_str: str) -> datetime:
        """
        Valida e converte a string de data para datetime.
        Formato esperado: YYYY-MM-DD
        Previne agendamentos em datas passadas.
        """
        try:
            data = datetime.strptime(data_str, "%Y-%m-%d")
        except ValueError:
            raise ValueError(
                f"Formato de data invalido: '{data_str}'. Use YYYY-MM-DD (ex: 2024-01-15)."
            )
        # Bloqueia agendamentos retroativos (Security by Design)
        if data.date() < datetime.now().date():
            raise ValueError("Nao e possivel agendar reunioes em datas passadas.")
        return data

    def _validar_hora(self, hora_str: str, tipo: str) -> datetime:
        """
        Valida se a hora informada esta dentro do horario permitido.
        Horarios validos: 09:00-12:00 (manha) e 13:30-17:30 (tarde).
        """
        try:
            # Extrai apenas a hora ignorando a data
            hora = datetime.strptime(hora_str, "%H:%M")
        except ValueError:
            raise ValueError(
                f"Formato de hora invalido: '{hora_str}'. Use HH:MM (ex: 09:00)."
            )

        # Verifica se a hora esta dentro de algum bloco permitido
        manha_inicio = datetime.strptime(HORARIOS_VALIDOS["manha"]["inicio"], "%H:%M")
        manha_fim = datetime.strptime(HORARIOS_VALIDOS["manha"]["fim"], "%H:%M")
        tarde_inicio = datetime.strptime(HORARIOS_VALIDOS["tarde"]["inicio"], "%H:%M")
        tarde_fim = datetime.strptime(HORARIOS_VALIDOS["tarde"]["fim"], "%H:%M")

        dentro_manha = manha_inicio <= hora <= manha_fim
        dentro_tarde = tarde_inicio <= hora <= tarde_fim

        if not (dentro_manha or dentro_tarde):
            raise ValueError(
                f"Hora invalida: {hora_str}. O horario permitido e "
                f"09:00-12:00 ou 13:30-17:30."
            )
        return hora

    def _validar_participantes(self, participantes: List[str]) -> List[str]:
        """
        Valida e sanitiza a lista de participantes.
        - Limpa espacos em branco
        - Valida formato de e-mail basico (regex)
        - Limite maximo de 50 participantes para evitar abusos
        """
        if len(participantes) > 50:
            raise ValueError("Numero maximo de participantes atingido: 50.")

        participantes_validos: List[str] = []
        padrao_email = re.compile(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        )

        for p in participantes:
            p = p.strip()
            if not p:
                continue
            # Sanitizacao: remove caracteres perigosos
            p = re.sub(r"[\x00-\x1f<>]", "", p)
            if not padrao_email.match(p):
                raise ValueError(f"E-mail invalido: '{p}'.")
            participantes_validos.append(p.lower())

        # Remove duplicatas mantendo a ordem
        return list(dict.fromkeys(participantes_validos))

    def _validar_duracao(self) -> None:
        """
        Valida que a duracao da reuniao e razoavel.
        - hora_fim deve ser maior que hora_inicio
        - duracao maxima: TEMPO_MAXIMO_REUNIAO minutos
        """
        # Junta data + hora para calcular a duracao real
        inicio = datetime.combine(self.data.date(), self.hora_inicio.time())
        fim = datetime.combine(self.data.date(), self.hora_fim.time())

        if fim <= inicio:
            raise ValueError("A hora de fim deve ser posterior a hora de inicio.")

        duracao = (fim - inicio).total_seconds() / 60
        if duracao > TEMPO_MAXIMO_REUNIAO:
            raise ValueError(
                f"Duracao da reuniao ({int(duracao)} min) excede o maximo permitido ({TEMPO_MAXIMO_REUNIAO} min)."
            )

    def validar(self) -> None:
        """Executa todas as validacoes da reuniao antes de persistir."""
        self._validar_duracao()

    # --- Metodos publicos ---

    def to_dict(self) -> dict:
        """Serializa a reuniao para dicionario (para JSON)."""
        return {
            "id": self.id,
            "titulo": self.titulo,
            "sala": self.sala,
            "data": self.data.strftime("%Y-%m-%d"),
            "hora_inicio": self.hora_inicio.strftime("%H:%M"),
            "hora_fim": self.hora_fim.strftime("%H:%M"),
            "participantes": self.participantes,
        }


# ============================================================
# CLASSE GESTOR SALAS
# ============================================================

class GestorSalas:
    """
    Gerencia o agendamento, cancelamento e listagem de reunioes.
    
    Responsabilidades:
        - Carregar e salvar agendamentos em arquivo JSON
        - Verificar conflitos de horario por sala
        - Agendar e cancelar reunioes
        - Listar reunioes por sala, data ou participante
    """

    def __init__(self, arquivo: str = ARQUIVO_AGENDAMENTOS):
        self.arquivo: str = arquivo
        # Lista interna de todas as reunioes (fonte unica de verdade)
        self.reunioes: List[Reuniao] = []
        self._carregar_agendamentos()

    # --- Persistencia ---

    def _carregar_agendamentos(self) -> None:
        """Carrega os agendamentos do arquivo JSON ao iniciar."""
        try:
            with open(self.arquivo, "r", encoding="utf-8") as f:
                dados = json.load(f)
                for item in dados:
                    # Reconstrói objetos Reuniao a partir do JSON
                    r = Reuniao(
                        titulo=item["titulo"],
                        sala=item["sala"],
                        data=item["data"],
                        hora_inicio=item["hora_inicio"],
                        hora_fim=item["hora_fim"],
                        participantes=item.get("participantes", []),
                    )
                    # Restaura o ID original (nao gera um novo)
                    r.id = item["id"]
                    self.reunioes.append(r)
        except FileNotFoundError:
            # Primeira execucao - arquivo nao existe ainda
            self.reunioes = []
        except json.JSONDecodeError:
            # Arquivo corrompido - inicia com lista vazia e alerta
            print(f"[AVISO] Arquivo {self.arquivo} corrompido. Iniciando com lista vazia.")
            self.reunioes = []

    def _salvar_agendamentos(self) -> None:
        """Salva todas as reunioes no arquivo JSON."""
        with open(self.arquivo, "w", encoding="utf-8") as f:
            json.dump(
                [r.to_dict() for r in self.reunioes],
                f,
                indent=2,
                ensure_ascii=False,
            )

    # --- Consultas ---

    def listar_reunioes(self) -> List[dict]:
        """Retorna todas as reunioes cadastradas em formato serializado."""
        return [r.to_dict() for r in self.reunioes]

    def listar_por_sala(self, sala: int) -> List[dict]:
        """Retorna reunioes de uma sala especifica."""
        return [r.to_dict() for r in self.reunioes if r.sala == sala]

    def listar_por_data(self, data: str) -> List[dict]:
        """Retorna reunioes de uma data especifica."""
        return [r.to_dict() for r in self.reunioes if r.data.strftime("%Y-%m-%d") == data]

    def listar_por_participante(self, email: str) -> List[dict]:
        """Retorna reunioes de um participante especifico."""
        email = email.strip().lower()
        return [
            r.to_dict() for r in self.reunioes if email in [p.lower() for p in r.participantes]
        ]

    # --- Verificacao de conflitos ---

    def _ha_conflito(self, nova: Reuniao) -> bool:
        """
        Verifica se a nova reuniao conflita com alguma ja agendada na mesma sala.
        Conflito ocorre quando os intervalos de horario se sobrepõem.
        """
        for existente in self.reunioes:
            # Mesma sala e mesma data
            if existente.sala == nova.sala and existente.data.date() == nova.data.date():
                # Constrói datetime completo para comparacao precisa
                novo_inicio = datetime.combine(nova.data.date(), nova.hora_inicio.time())
                novo_fim = datetime.combine(nova.data.date(), nova.hora_fim.time())
                existente_inicio = datetime.combine(
                    existente.data.date(), existente.hora_inicio.time()
                )
                existente_fim = datetime.combine(
                    existente.data.date(), existente.hora_fim.time()
                )
                # Sobreposicao: inicio < fim_existente E fim > inicio_existente
                if novo_inicio < existente_fim and novo_fim > existente_inicio:
                    return True
        return False

    def verificar_disponibilidade(self, sala: int, data: str, hora_inicio: str, hora_fim: str) -> bool:
        """
        Verifica se uma sala esta disponivel para um horario proposto.
        Retorna True se disponivel, False se houver conflito.
        """
        try:
            nova = Reuniao(
                titulo="__check__",
                sala=sala,
                data=data,
                hora_inicio=hora_inicio,
                hora_fim=hora_fim,
                participantes=[],
            )
            nova.validar()
            return not self._ha_conflito(nova)
        except ValueError:
            # Se a validacao falhar, considera indisponivel por seguranca
            return False

    # --- Operacoes ---

    def agendar_reuniao(
        self,
        titulo: str,
        sala: int,
        data: str,
        hora_inicio: str,
        hora_fim: str,
        participantes: Optional[List[str]] = None,
    ) -> Reuniao:
        """
        Agenda uma nova reuniao apos validar todos os campos e verificar conflitos.
        Levanta excecoes em caso de erro (input invalido, conflito, etc).
        """
        reuniao = Reuniao(titulo, sala, data, hora_inicio, hora_fim, participantes)
        reuniao.validar()

        if self._ha_conflito(reuniao):
            raise ValueError(
                f"Conflito: a sala {sala} ja esta ocupada nesse horario em {data}."
            )

        self.reunioes.append(reuniao)
        self._salvar_agendamentos()
        print(f"[SUCESSO] Reuniao '{reuniao.titulo}' agendada. ID: {reuniao.id}")
        return reuniao

    def cancelar_reuniao(self, id_reuniao: str) -> bool:
        """Cancela (remove) uma reuniao pelo ID. Retorna True se encontrada."""
        for i, r in enumerate(self.reunioes):
            if r.id == id_reuniao:
                titulo = r.titulo
                del self.reunioes[i]
                self._salvar_agendamentos()
                print(f"[SUCESSO] Reuniao '{titulo}' cancelada.")
                return True
        print(f"[AVISO] Reuniao com ID '{id_reuniao}' nao encontrada.")
        return False


# ============================================================
# INTERFACE DE LINCA DE COMANDO (CLI)
# ============================================================

def exibir_menu() -> None:
    """Exibe o menu de opcoes para o usuario."""
    print("\n" + "=" * 60)
    print("  GESTOR DE SALAS DE REUNIAO - MENU PRINCIPAL")
    print("=" * 60)
    print("1. Agendar uma reuniao")
    print("2. Cancelar uma reuniao")
    print("3. Listar todas as reunioes")
    print("4. Listar reunioes por sala")
    print("5. Listar reunioes por data")
    print("6. Listar reunioes por participante")
    print("7. Verificar disponibilidade de sala")
    print("0. Sair")
    print("=" * 60)


def obter_input(mensagem: str) -> str:
    """Leitura de entrada com sanitizacao basica."""
    return input(mensagem).strip()


def obter_participantes() -> List[str]:
    """
    Le uma lista de e-mails separados por virgula.
    Exemplo: alice@empresa.com, bob@empresa.com
    """
    entrada = obter_input("Participantes (e-mails separados por virgula): ")
    if not entrada:
        return []
    return [p.strip() for p in entrada.split(",") if p.strip()]


def main() -> None:
    """
    Funcao principal - loop interativo da CLI.
    Inicializa o gestor e processa comandos do usuario.
    """
    gestor = GestorSalas()
    print(f"\nBem-vindo ao Gestor de Salas de Reuniao!")
    print(f"Salas disponiveis: 1 a {NUMERO_SALAS}")
    print(f"Horarios validos: 09:00-12:00 e 13:30-17:30")

    while True:
        exibir_menu()
        opcao = obter_input("Selecione uma opcao: ")

        # --- Opcao 1: Agendar ---
        if opcao == "1":
            try:
                titulo = obter_input("Titulo da reuniao: ")
                sala = int(obter_input("Numero da sala (1-10): "))
                data = obter_input("Data (YYYY-MM-DD): ")
                hora_inicio = obter_input("Hora inicio (HH:MM): ")
                hora_fim = obter_input("Hora fim (HH:MM): ")
                participantes = obter_participantes()
                gestor.agendar_reuniao(
                    titulo, sala, data, hora_inicio, hora_fim, participantes
                )
            except ValueError as e:
                print(f"[ERRO] {e}")
            except Exception as e:
                # Tratamento genercio para erros inesperados (fail-safe)
                print(f"[ERRO INESPERADO] {e}")

        # --- Opcao 2: Cancelar ---
        elif opcao == "2":
            id_reuniao = obter_input("ID da reuniao a cancelar: ")
            gestor.cancelar_reuniao(id_reuniao)

        # --- Opcao 3: Listar todas ---
        elif opcao == "3":
            reunioes = gestor.listar_reunioes()
            if not reunioes:
                print("\nNenhuma reuniao agendada.")
            else:
                print("\n" + "-" * 60)
                for r in reunioes:
                    print(
                        f"[{r['id']}] Sala {r['sala']}, {r['data']} "
                        f"{r['hora_inicio']}-{r['hora_fim']} | {r['titulo']} "
                        f"| Participantes: {len(r['participantes'])}"
                    )
                print("-" * 60)

        # --- Opcao 4: Listar por sala ---
        elif opcao == "4":
            try:
                sala = int(obter_input("Numero da sala (1-10): "))
                reunioes = gestor.listar_por_sala(sala)
                print(f"\nReunioes da sala {sala}:")
                for r in reunioes:
                    print(f"  {r['data']} {r['hora_inicio']}-{r['hora_fim']} | {r['titulo']}")
                if not reunioes:
                    print("  Nenhuma reuniao nesta sala.")
            except ValueError as e:
                print(f"[ERRO] {e}")

        # --- Opcao 5: Listar por data ---
        elif opcao == "5":
            data = obter_input("Data (YYYY-MM-DD): ")
            reunioes = gestor.listar_por_data(data)
            print(f"\nReunioes em {data}:")
            for r in reunioes:
                print(
                    f"  Sala {r['sala']} | {r['hora_inicio']}-{r['hora_fim']} "
                    f"| {r['titulo']}"
                )
            if not reunioes:
                print("  Nenhuma reuniao nesta data.")

        # --- Opcao 6: Listar por participante ---
        elif opcao == "6":
            email = obter_input("E-mail do participante: ")
            reunioes = gestor.listar_por_participante(email)
            print(f"\nReunioes de {email}:")
            for r in reunioes:
                print(
                    f"  Sala {r['sala']} | {r['data']} {r['hora_inicio']}-{r['hora_fim']} "
                    f"| {r['titulo']}"
                )
            if not reunioes:
                print("  Nenhuma reuniao para este participante.")

        # --- Opcao 7: Verificar disponibilidade ---
        elif opcao == "7":
            try:
                sala = int(obter_input("Numero da sala (1-10): "))
                data = obter_input("Data (YYYY-MM-DD): ")
                hora_inicio = obter_input("Hora inicio (HH:MM): ")
                hora_fim = obter_input("Hora fim (HH:MM): ")
                disponivel = gestor.verificar_disponibilidade(
                    sala, data, hora_inicio, hora_fim
                )
                status = "DISPONIVEL" if disponivel else "OCUPADA"
                print(f"\nSala {sala} em {data} das {hora_inicio} as {hora_fim}: {status}")
            except ValueError as e:
                print(f"[ERRO] {e}")

        # --- Opcao 0: Sair ---
        elif opcao == "0":
            print("\nSaindo do gestor. Ate logo!")
            break

        else:
            print("\n[AVISO] Opcoo invalida. Tente novamente.")


# ============================================================
# PONTO DE ENTRADA
# ============================================================

if __name__ == "__main__":
    main()
