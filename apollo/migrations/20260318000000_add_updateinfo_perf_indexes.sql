-- migrate:up
create index advisory_packages_advisory_repo_product_idx
    on advisory_packages (advisory_id, repo_name, supported_product_id);

create index advisory_affected_products_spid_major_arch_idx
    on advisory_affected_products (supported_product_id, major_version, arch);


-- migrate:down
drop index if exists advisory_packages_advisory_repo_product_idx;
drop index if exists advisory_affected_products_spid_major_arch_idx;
