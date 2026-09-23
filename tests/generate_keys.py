from aat.keys import generate_key_pair


def main():
    generate_key_pair("issuer")
    generate_key_pair("agent-a")
    generate_key_pair("agent-b")
    generate_key_pair("tool-agent")

    print("Keys generated.")


if __name__ == "__main__":
    main()
