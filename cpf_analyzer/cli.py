from __future__ import annotations

import argparse
import sys

from .core import generate_fake_cpf
from .report import analyze, to_json
from .batch import load_inputs, run_batch, write_json, write_csv


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cpf-smart",
        description="Analisador Inteligente de CPF (simulado) - valida, mascara, sinaliza padrões e gera relatório."
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    p_analyze = sub.add_parser("analyze", help="Analisa um CPF informado")
    p_analyze.add_argument("cpf", help="CPF para analisar (com ou sem pontuação)")
    p_analyze.add_argument("--json", action="store_true", help="Imprime relatório em JSON")
    p_analyze.add_argument("--pretty", action="store_true", help="JSON identado")

    p_gen = sub.add_parser("generate", help="Gera CPFs fictícios válidos para teste")
    p_gen.add_argument("-n", "--count", type=int, default=5, help="Quantidade para gerar (padrão: 5)")
    p_gen.add_argument("--raw", action="store_true", help="Gera sem formatação (apenas dígitos)")

    p_batch = sub.add_parser("batch", help="Analisa CPFs em lote a partir de .txt ou .csv")
    p_batch.add_argument("input", help="Caminho do arquivo .txt ou .csv")
    p_batch.add_argument("--column", default="cpf", help="Nome da coluna no CSV (padrão: cpf)")
    p_batch.add_argument("--out-json", default="batch_report.json", help="Arquivo JSON de saída")
    p_batch.add_argument("--out-csv", default="batch_report.csv", help="Arquivo CSV de saída")
    p_batch.add_argument("--print-summary", action="store_true", help="Imprime resumo no terminal")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "generate":
        for _ in range(args.count):
            print(generate_fake_cpf(formatted=not args.raw))
        return 0

    if args.cmd == "analyze":
        rep = analyze(args.cpf)
        if args.json:
            print(to_json(rep, pretty=True if args.pretty else True))
            return 0

        a = rep["analysis"]
        print(f"Entrada: {a['raw_input']}")
        print(f"Normalizado: {a['digits']}")
        print(f"Formatado: {a['formatted']}")
        print(f"Mascarado: {a['masked']}")
        print(f"Válido: {a['is_valid']}")
        if not a["is_valid"]:
            print(f"Motivo: {a['reason']}")
        print(f"Risco: {rep['risk_level']} ({rep['risk_score']}/100)")
        if rep["flags"]:
            print("\nFlags:")
            for f in rep["flags"]:
                print(f"- [{f['severity']}] {f['code']}: {f['message']}")
        return 0

    if args.cmd == "batch":
        values = load_inputs(args.input, column=args.column)
        payload = run_batch(values)

        write_json(args.out_json, payload, pretty=True)
        write_csv(args.out_csv, payload["items"])

        if args.print_summary:
            s = payload["summary"]
            print(f"Total: {s['total']}")
            print(f"Válidos: {s['valid']} | Inválidos: {s['invalid']}")
            print(f"Risco low/medium/high: {s['risk_low']}/{s['risk_medium']}/{s['risk_high']}")
            print(f"JSON: {args.out_json}")
            print(f"CSV: {args.out_csv}")

        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))