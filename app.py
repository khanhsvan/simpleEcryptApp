from simple_encrypt_app.ui import create_app


def main() -> None:
    root = create_app()
    root.mainloop()


if __name__ == "__main__":
    main()
