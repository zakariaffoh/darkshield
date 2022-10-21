
## Install OpenSSL: https://docs.rs/openssl/latest/openssl/

### Windows
1-  Install vcpkg and add VCPKG_ROOT env variable pointint to the base folder of vcpkg install.
2-  Add vcpkg install to the system PATH, then vcpk command can be found.
3-  Build and install openssl

    >> vcpkg install  --triplet=x64-windows-static-md openssl 

4- OpenSSLL run can now be installed

## Run Docker Postgres
    >> docker run --name darkshield-db -e POSTGRES_PASSWORD=password -e POSTGRES_USER=user -e POSTGRES_DB=darkshield_dev -d postgres