#!/usr/bin/env bash
set -euo pipefail

# ========= PARSE ARGUMENTS =========
SEEDS_ONLY=false
START_VMS=false
RUN_BOOTSTRAP=false
CLEAN=false
while [[ $# -gt 0 ]]; do
  case $1 in
    --seeds-only)
      SEEDS_ONLY=true
      shift
      ;;
    --start-vms)
      START_VMS=true
      shift
      ;;
    --bootstrap)
      START_VMS=true
      RUN_BOOTSTRAP=true
      shift
      ;;
    --clean)
      CLEAN=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--seeds-only] [--start-vms] [--bootstrap]"
      exit 1
      ;;
  esac
done

# ========= LOAD ENV =========
if [[ -f .env ]]; then
  set -a
  # shellcheck source=/dev/null
  source .env
  set +a
fi

# ========= CONFIG WITH DEFAULTS =========
CLUSTER_NAME="${CLUSTER_NAME:-talos-pve}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-1.33.6}"
TALOS_VERSION="${TALOS_VERSION:-1.12.1}"

# Proxmox storage/ISO/bridge
STORAGE_ISO_NAME="${STORAGE_ISO_NAME:-local}"         # имя ISO storage Proxmox
STORAGE_IMAGE_NAME="${STORAGE_IMAGE_NAME:-local-lvm}" # имя ISO storage Proxmox
ISO_DIR="${ISO_DIR:-/var/lib/vz/template/iso}"        # директория с ISO
BRIDGE_NAME="${BRIDGE_NAME:-vmbr1}"                   # сетевой bridge

# Control plane config
CP_COUNT="${CP_COUNT:-3}"
CP_CPU="${CP_CPU:-2}"
CP_RAM="${CP_RAM:-4}"       # GiB
CP_DISK="${CP_DISK:-20}"    # GiB

# Workers config
WK_COUNT="${WK_COUNT:-3}"
WK_CPU="${WK_CPU:-4}"
WK_RAM="${WK_RAM:-16}"
WK_DISK="${WK_DISK:-100}"
WK_EXTRA_DISK_ENABLED="${WK_EXTRA_DISK_ENABLED:-false}"
WK_EXTRA_DISK_SIZE="${WK_EXTRA_DISK_SIZE:-100}"

# Talos images
ISO_URL="${ISO_URL:-https://factory.talos.dev/image/2fcc09d8cccf7fea0f198ba11e0238cad9c885ad2dfab9fb39192437f4c7ed2d/v1.11.5/metal-amd64.iso}"
ISO_INSTALLER_URL="${ISO_INSTALLER_URL:-factory.talos.dev/metal-installer/2fcc09d8cccf7fea0f198ba11e0238cad9c885ad2dfab9fb39192437f4c7ed2d:v1.11.5}"
ISO_LOCAL_PATH="${ISO_LOCAL_PATH:-${ISO_DIR}/metal-amd64.iso}"

VM_BASE_NAME_CP="${VM_BASE_NAME_CP:-${CLUSTER_NAME}-cp}"
VM_BASE_NAME_WK="${VM_BASE_NAME_WK:-${CLUSTER_NAME}-wk}"

# Базовые VMID (vmid = base + index-1)
CP_VMID_BASE="${CP_VMID_BASE:-900}"
WK_VMID_BASE="${WK_VMID_BASE:-910}"

RECONCILE="${RECONCILE:-true}"

# IP parameters
GATEWAY="${GATEWAY:-192.168.10.1}"
CIDR_PREFIX="${CIDR_PREFIX:-24}"

# DNS servers
if [[ -n "${DNS_SERVER:-}" ]]; then
  IFS=',' read -r -a DNS_SERVER <<< "$DNS_SERVER"
else
  DNS_SERVER=("8.8.8.8" "1.1.1.1")
fi

# Control-plane IPs
if [[ -n "${CP_IPS:-}" ]]; then
  IFS=',' read -r -a CP_IPS <<< "$CP_IPS"
else
  CP_IPS=("192.168.10.2" "192.168.10.3" "192.168.10.4")
fi

# Worker IPs
if [[ -n "${WK_IPS:-}" ]]; then
  IFS=',' read -r -a WK_IPS <<< "$WK_IPS"
else
  WK_IPS=("192.168.10.10" "192.168.10.11" "192.168.10.12")
fi

# Внешние адреса для certSANs (необязательно)
if [[ -n "${EXTERNAL_IPS:-}" ]]; then
  IFS=',' read -r -a EXTERNAL_IPS <<< "$EXTERNAL_IPS"
else
  EXTERNAL_IPS=()
fi

VIP_IP="${VIP_IP:-192.168.10.50}"

SEEDS_DIR="${SEEDS_DIR:-$(pwd)/seeds}"

# ========= Helpers =========

ensure_storage_exists() {
  if ! pvesm status | awk 'NR>1 {print $1}' | grep -qx "$STORAGE_ISO_NAME"; then
    echo "Storage '$STORAGE_ISO_NAME' not found in Proxmox (pvesm status)."
    exit 1
  fi

  if ! pvesm status | awk 'NR>1 {print $1}' | grep -qx "$STORAGE_IMAGE_NAME"; then
    echo "Storage '$STORAGE_IMAGE_NAME' not found in Proxmox (pvesm status)."
    exit 1
  fi
}

import_iso_if_needed() {
  mkdir -p "$ISO_DIR"
  if [[ ! -f "$ISO_LOCAL_PATH" ]]; then
    echo "Downloading Talos ISO..."
    curl -Lo "$ISO_LOCAL_PATH" "$ISO_URL" || {
      echo "Failed to download Talos ISO"
      exit 1
    }
  else
    echo "Talos ISO already exists at $ISO_LOCAL_PATH"
  fi
  echo "Talos ISO ready at $ISO_LOCAL_PATH (storage: $STORAGE_ISO_NAME)"
}

vmid_for_cp() {
  local index="$1"
  echo $((CP_VMID_BASE + index - 1))
}

vmid_for_wk() {
  local index="$1"
  echo $((WK_VMID_BASE + index - 1))
}

get_vmid_by_name() {
  local name="$1"
  qm list | awk -v n="$name" '$2 == n {print $1}' | head -n1
}

vm_exists_by_name() {
  local name="$1"
  local id
  id=$(get_vmid_by_name "$name" || true)
  [[ -n "$id" ]]
}

destroy_vm_by_vmid() {
  local vmid="$1"
  if qm status "$vmid" 2>/dev/null | grep -q "status: running"; then
    qm stop "$vmid" --skiplock || true
    sleep 2
  fi
  qm destroy "$vmid" --purge 2>/dev/null || true
}

create_seed_iso_from_mc() {
  local vmname="$1"
  local ip="$2"
  local role="$3"
  local out_iso="${ISO_DIR}/${vmname}-seed.iso"

  local src_dir="${SEEDS_DIR}/${vmname}"
  mkdir -p "$src_dir"

  local config_file
  if [[ "$role" == "cp" ]]; then
    config_file="$(pwd)/config/controlplane.yaml"
  else
    config_file="$(pwd)/config/worker.yaml"
  fi

  if [[ ! -f "$config_file" ]]; then
    echo "Config not found: $config_file"
    exit 1
  fi

  local ip_cidr="${ip}/${CIDR_PREFIX}"

  # Базовый конфиг
  local config
  config=$(yq eval '... comments=""' "$config_file" | \
    yq '.machine.network.hostname = "'"${vmname}"'"' | \
    yq '.machine.network.interfaces[0].interface = "ens18"' | \
    yq '.machine.network.interfaces[0].dhcp = false' | \
    yq '.machine.network.interfaces[0].routes[0].gateway = "'"${GATEWAY}"'"' | \
    yq '.machine.network.interfaces[0].addresses[0] = "'"$ip_cidr"'"' | \
    yq '.machine.time.servers[0] = "pool.ntp.org"' | \
    yq '.machine.install.image = "'"${ISO_INSTALLER_URL}"'"' | \
    yq '.machine.install.wipe = true' | \
    yq '.machine.install.disk = "/dev/sda"')

  for dns in "${DNS_SERVER[@]}"; do
    config=$(echo "$config" | yq eval '.machine.network.nameservers += ["'"$dns"'"]')
  done

  if [[ "$role" == "cp" ]]; then
    config=$(echo "$config" | \
      yq '.machine.network.interfaces[0].vip.ip = "'"${VIP_IP}"'"' | \
      yq '.cluster.network.cni.name = "none"'
    )

    for cp_ip in "${CP_IPS[@]}"; do
      config=$(echo "$config" | yq eval '.cluster.apiServer.certSANs += ["'"$cp_ip"'"]')
    done

    for ext_ip in "${EXTERNAL_IPS[@]}"; do
      config=$(echo "$config" | yq eval '.cluster.apiServer.certSANs += ["'"$ext_ip"'"]')
    done
  fi

  echo "$config" > "${src_dir}/config.yaml"

  if [[ "$SEEDS_ONLY" == "false" ]]; then
    genisoimage -quiet -volid "metal-iso" -joliet -rock -o "$out_iso" -graft-points "config.yaml=${src_dir}/config.yaml"
    echo "$out_iso"
  else
    echo "Seed config created: ${src_dir}/config.yaml"
    echo ""
  fi
}

attach_talos_iso() {
  local vmid="$1"
  local iso_path="$2"

  if [[ ! -f "$iso_path" ]]; then
    echo "Talos ISO not found at $iso_path"
    exit 1
  fi

  local iso_name
  iso_name=$(basename "$iso_path")

  # Для directory-сторожа: path как STORAGE_ISO_NAME:iso/filename.iso
  qm set "$vmid" --ide2 "${STORAGE_ISO_NAME}:iso/${iso_name},media=cdrom" >/dev/null

  qm set "$vmid" --boot order='scsi0;ide2' >/dev/null
}

attach_seed_iso() {
  local vmid="$1"
  local iso_path="$2"

  if [[ ! -f "$iso_path" ]]; then
    echo "Seed ISO not found at $iso_path"
    exit 1
  fi

  local iso_name
  iso_name=$(basename "$iso_path")

  # Подключаем вторым CD-ROM
  qm set "$vmid" --ide3 "${STORAGE_ISO_NAME}:iso/${iso_name},media=cdrom" >/dev/null
}

create_vm() {
  local name="$1"
  local vmid="$2"
  local vcpu="$3"
  local ram_gib="$4"
  local disk_gib="$5"
  local bridge="$6"
  local extra_disk_gib="${7:-0}"

  if qm config "$vmid" &>/dev/null; then
    echo "VMID $vmid already exists, refusing to overwrite"
    exit 1
  fi

  local mem_mb=$((ram_gib * 1024))

  qm create "$vmid" \
    --name "$name" \
    --memory "$mem_mb" \
    --cores "$vcpu" \
    --sockets 1 \
    --cpu host \
    --net0 "virtio,bridge=${bridge}" \
    --ostype l26 \
    --scsihw virtio-scsi-pci >/dev/null

  # Включаем QEMU Guest Agent
  qm set "$vmid" --agent enabled=1 >/dev/null

  # Основной диск
  qm set "$vmid" --scsi0 "${STORAGE_IMAGE_NAME}:${disk_gib}" >/dev/null

  # Дополнительный диск
  if [[ "${extra_disk_gib}" -gt 0 ]]; then
    qm set "$vmid" --scsi1 "${STORAGE_IMAGE_NAME}:${extra_disk_gib}" >/dev/null
  fi

  # Автостарт
  qm set "$vmid" --onboot 1 >/dev/null

  echo "$vmid"
}

reconcile_group() {
  # $1 base name, $2 desired count, $3 role(cp|wk), $4 vcpu, $5 ramGiB, $6 diskGiB, $7 extra_disk_gib
  local base="$1"
  local desired="$2"
  local role="$3"
  local vcpu="$4"
  local ram="$5"
  local disk="$6"
  local extra_disk="${7:-0}"

  if [[ "$SEEDS_ONLY" == "true" ]]; then
    echo "Generating seed configs for ${base}..."
    for i in $(seq 1 "$desired"); do
      local name="${base}${i}"
      local ip=""
      if [[ "$role" == "cp" ]]; then
        ip="${CP_IPS[$((i-1))]}"
      else
        ip="${WK_IPS[$((i-1))]}"
      fi
      if [[ -z "$ip" ]]; then
        echo "No IP configured for $name, skip."
        continue
      fi
      create_seed_iso_from_mc "$name" "$ip" "$role"
    done
    return 0
  fi

  # Создаём недостающие
  for i in $(seq 1 "$desired"); do
    local name="${base}${i}"
    local vmid=""
    if [[ "$role" == "cp" ]]; then
      vmid=$(vmid_for_cp "$i")
    else
      vmid=$(vmid_for_wk "$i")
    fi

    if vm_exists_by_name "$name" || qm config "$vmid" &>/dev/null; then
      echo "VM exists: $name (vmid=$vmid)"
      continue
    fi

    local ip=""
    if [[ "$role" == "cp" ]]; then
      ip="${CP_IPS[$((i-1))]}"
    else
      ip="${WK_IPS[$((i-1))]}"
    fi
    if [[ -z "$ip" ]]; then
      echo "No IP configured for $name, skip."
      continue
    fi

    local created_vmid
    created_vmid=$(create_vm "$name" "$vmid" "$vcpu" "$ram" "$disk" "$BRIDGE_NAME" "$extra_disk")
    echo "VM created: $name (vmid=$created_vmid)"
    attach_talos_iso "$created_vmid" "$ISO_LOCAL_PATH"
    local seed_iso
    seed_iso=$(create_seed_iso_from_mc "$name" "$ip" "$role")
    echo "Seed ISO: $seed_iso"
    attach_seed_iso "$created_vmid" "$seed_iso"
    echo "Configured VM: $name ($ip) vmid=$created_vmid"
  done

  # Удаляем лишние (индекс > desired)
  if [[ "${RECONCILE}" == "true" ]]; then
    # Выберем по имени
    qm list | awk 'NR>1 {print $1, $2}' | while read -r id nm; do
      if [[ "$nm" =~ ^${base}([0-9]+)$ ]]; then
        local idx="${BASH_REMATCH[1]}"
        if [[ "$idx" -gt "$desired" ]]; then
          echo "Removing extra VM: $nm (vmid=$id)"
          destroy_vm_by_vmid "$id"
        fi
      fi
    done
  fi
}

check_and_install() {

  if ! command -v talosctl >/dev/null 2>&1; then
    echo "Install talosctl"
    curl -sL https://talos.dev/install | sh
    echo "DONE"
  fi

  if ! command -v genisoimage >/dev/null 2>&1; then
    echo "Install genisoimage"
    apt-get update -y >/dev/null
    apt-get install -y genisoimage >/dev/null
    echo "DONE"
  fi

  if ! command -v yq >/dev/null 2>&1; then
    echo "Install yq"
    wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/local/bin/yq
    chmod +x /usr/local/bin/yq
    echo "DONE"
  fi

  if ! command -v kubectl >/dev/null 2>&1; then
    curl -LO "https://dl.k8s.io/release/v1.28.2/bin/linux/amd64/kubectl"
    chmod +x kubectl
    mv kubectl /usr/local/bin/
  fi

  if ! command -v helm >/dev/null 2>&1; then
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
  fi
}

generate_config() {
  local config_dir
  config_dir="$(pwd)/config"
  mkdir -p "$config_dir"

  if [[ ! -f "$config_dir/controlplane.yaml" ]] || [[ ! -f "$config_dir/worker.yaml" ]]; then
    talosctl gen config --kubernetes-version="$KUBERNETES_VERSION" --talos-version="$TALOS_VERSION" "$CLUSTER_NAME" "https://${CP_IPS[0]}:6443" -o "$config_dir"
    echo "Generated new Talos config files in $config_dir"
  else
    echo "Config files already exist in $config_dir, skipping generation"
  fi

  talosctl --talosconfig "$(pwd)/config/talosconfig" config endpoints "${CP_IPS[@]}"
}

clean_seeds() {
  mkdir -p "$(pwd)/config"
  rm -rf "$(pwd)/seeds/${CLUSTER_NAME}"* || true
  rm -f "${ISO_DIR}/${CLUSTER_NAME}"* || true
}

start_all_vms() {
  echo "Starting all cluster VMs..."

  for i in $(seq 1 "$CP_COUNT"); do
    local name="${VM_BASE_NAME_CP}${i}"
    local vmid
    vmid=$(get_vmid_by_name "$name" || true)
    if [[ -n "$vmid" ]]; then
      if ! qm status "$vmid" 2>/dev/null | grep -q "status: running"; then
        echo "Starting $name (vmid=$vmid)..."
        qm start "$vmid"
      else
        echo "$name is already running"
      fi
    fi
  done

  for i in $(seq 1 "$WK_COUNT"); do
    local name="${VM_BASE_NAME_WK}${i}"
    local vmid
    vmid=$(get_vmid_by_name "$name" || true)
    if [[ -n "$vmid" ]]; then
      if ! qm status "$vmid" 2>/dev/null | grep -q "status: running"; then
        echo "Starting $name (vmid=$vmid)..."
        qm start "$vmid"
      else
        echo "$name is already running"
      fi
    fi
  done
}

wait_for_talos_api() {
  echo "Waiting for Talos API to become available..."
  local max_attempts=60
  local attempt=0
  local all_ready=false

  while [[ $attempt -lt $max_attempts ]]; do
    all_ready=true

    for ip in "${CP_IPS[@]}"; do
      if ! talosctl --talosconfig "$(pwd)/config/talosconfig" \
        --nodes "$ip" version &>/dev/null; then
        echo "Waiting for Talos API on $ip... (attempt $((attempt+1))/$max_attempts)"
        all_ready=false
        break
      fi
    done

    if [[ "$all_ready" == "true" ]]; then
      echo "All control plane nodes are responding to Talos API"
      return 0
    fi

    attempt=$((attempt+1))
    sleep 5
  done

  echo "Error: Talos API did not become available within expected time"
  return 1
}

bootstrap_cluster() {
  echo "Bootstrapping Talos cluster..."

  local bootstrap_node="${CP_IPS[0]}"
  echo "Bootstrapping from node: $bootstrap_node"

  local max_attempts=10
  local attempt=1
  while [[ $attempt -le $max_attempts ]]; do
    echo "Running talos bootstrap (attempt ${attempt}/${max_attempts})..."
    if talosctl --talosconfig "$(pwd)/config/talosconfig" \
      --nodes "$bootstrap_node" \
      bootstrap; then
      echo "Bootstrap command succeeded"
      break
    fi

    if [[ $attempt -ge $max_attempts ]]; then
      echo "Error: talos bootstrap failed after $max_attempts attempts"
      return 1
    fi

    echo "Bootstrap failed. Retrying in 5 seconds..."
    sleep 5
    attempt=$((attempt+1))
  done

  echo "Bootstrap command sent. Waiting for Kubernetes to initialize..."

  local max_wait=120
  local waited=0
  while [[ $waited -lt $max_wait ]]; do
    if talosctl --talosconfig "$(pwd)/config/talosconfig" \
      --nodes "$bootstrap_node" \
      kubeconfig "$(pwd)/config/kubeconfig" 2>/dev/null; then
      echo "Kubeconfig successfully retrieved"
      break
    fi
    echo "Waiting for Kubernetes API... ($waited/$max_wait seconds)"
    sleep 10
    waited=$((waited+10))
  done

  if [[ $waited -ge $max_wait ]]; then
    echo "Warning: Could not retrieve kubeconfig within expected time"
    return 1
  fi

  echo "Cluster bootstrap completed successfully"
  return 0
}

install_cilium() {
  echo "Installing Cilium CNI via Helm..."

  export KUBECONFIG="$(pwd)/config/kubeconfig"

  echo "Waiting for Kubernetes API to be ready..."
  local max_attempts=60
  local attempt=0
  while [[ $attempt -lt $max_attempts ]]; do
    if kubectl get nodes &>/dev/null; then
      echo "Kubernetes API is ready"
      break
    fi
    echo "Waiting for Kubernetes API... (attempt $((attempt+1))/$max_attempts)"
    sleep 5
    attempt=$((attempt+1))
  done

  if [[ $attempt -ge $max_attempts ]]; then
    echo "Error: Kubernetes API did not become ready"
    return 1
  fi

  echo "Adding Cilium Helm repository..."
  helm repo add cilium https://helm.cilium.io/
  helm repo update

  echo "Installing Cilium..."
  helm install \
      cilium \
      cilium/cilium \
      --version 1.18.0 \
      --namespace kube-system \
      --set ipam.mode=kubernetes \
      --set kubeProxyReplacement=true \
      --set securityContext.capabilities.ciliumAgent="{CHOWN,KILL,NET_ADMIN,NET_RAW,IPC_LOCK,SYS_ADMIN,SYS_RESOURCE,DAC_OVERRIDE,FOWNER,SETGID,SETUID}" \
      --set securityContext.capabilities.cleanCiliumState="{NET_ADMIN,SYS_ADMIN,SYS_RESOURCE}" \
      --set cgroup.autoMount.enabled=false \
      --set cgroup.hostRoot=/sys/fs/cgroup \
      --set k8sServiceHost=localhost \
      --set k8sServicePort=7445

  if [[ $? -ne 0 ]]; then
    echo "Error: Failed to install Cilium"
    return 1
  fi

  echo "Waiting for Cilium pods to be ready..."

  local wait_attempts=0
  local max_wait_attempts=10
  local wait_success=false

  while [[ $wait_attempts -lt $max_wait_attempts ]]; do
    wait_attempts=$((wait_attempts+1))
    echo "Attempt $wait_attempts/$max_wait_attempts: Waiting for Cilium pods..."

    if kubectl wait --for=condition=ready pod \
      --selector=k8s-app=cilium \
      --namespace=kube-system \
      --timeout=300s 2>/dev/null; then
      wait_success=true
      break
    else
      echo "Wait attempt $wait_attempts failed. Checking pod status..."
      kubectl get pods -n kube-system -l k8s-app=cilium 2>/dev/null || true

      if [[ $wait_attempts -lt $max_wait_attempts ]]; then
        echo "Retrying in 10 seconds..."
        sleep 10
      fi
    fi
  done

  if [[ "$wait_success" != "true" ]]; then
    echo "Error: Cilium pods did not become ready after $max_wait_attempts attempts"
    echo "Current pod status:"
    kubectl get pods -n kube-system -l k8s-app=cilium
    return 1
  fi

  echo "Cilium CNI installed successfully"
  return 0
}

clean_all_cluster_resources() {
  echo "Cleaning all cluster VMs and local data for cluster '${CLUSTER_NAME}'..."

  # Удаляем все ВМ с именами, начинающимися на VM_BASE_NAME_CP/VM_BASE_NAME_WK
  qm list | awk 'NR>1 {print $1, $2}' | while read -r id nm; do
    if [[ "$nm" =~ ^${VM_BASE_NAME_CP}[0-9]+$ ]] || [[ "$nm" =~ ^${VM_BASE_NAME_WK}[0-9]+$ ]]; then
      echo "Removing VM: $nm (vmid=$id)"
      destroy_vm_by_vmid "$id"
    fi
  done

  # Удаляем локальные конфиги и сиды целиком
#  rm -rf "$(pwd)/config" || true
  rm -rf "$(pwd)/seeds" || true

  # По возможности удалим seed ISO из директории ISO
  rm -f "${ISO_DIR}/${VM_BASE_NAME_CP}"*-seed.iso 2>/dev/null || true
  rm -f "${ISO_DIR}/${VM_BASE_NAME_WK}"*-seed.iso 2>/dev/null || true

  echo "Clean completed."
}

main() {
  echo "Preparing..."

  if [[ "$CLEAN" == "true" ]]; then
    # Режим полной очистки и выход
    clean_all_cluster_resources
    return 0
  fi

  ensure_storage_exists
  check_and_install
  clean_seeds
  generate_config

  # Проверки размеров массивов IP
  if [ "$CP_COUNT" -gt "${#CP_IPS[@]}" ]; then
    echo "Error: CP_COUNT ($CP_COUNT) exceeds CP_IPS array size (${#CP_IPS[@]})"
    exit 1
  fi

  if [ "$WK_COUNT" -gt "${#WK_IPS[@]}" ]; then
    echo "Error: $WK_COUNT ($WK_COUNT) exceeds WK_IPS array size (${#WK_IPS[@]})"
    exit 1
  fi

  if [[ "$SEEDS_ONLY" == "true" ]]; then
    echo "Running in seeds-only mode..."
    reconcile_group "$VM_BASE_NAME_CP" "$CP_COUNT" "cp" "$CP_CPU" "$CP_RAM" "$CP_DISK" 0
    reconcile_group "$VM_BASE_NAME_WK" "$WK_COUNT" "wk" "$WK_CPU" "$WK_RAM" "$WK_DISK" "$WK_EXTRA_DISK_SIZE"
    echo "Done. Seed configs generated in $SEEDS_DIR"
    return 0
  fi

  import_iso_if_needed

  # Control plane
  reconcile_group "$VM_BASE_NAME_CP" "$CP_COUNT" "cp" "$CP_CPU" "$CP_RAM" "$CP_DISK" 0

  # Workers
  local wk_extra_size=0
  if [[ "$WK_EXTRA_DISK_ENABLED" == "true" ]]; then
    wk_extra_size="$WK_EXTRA_DISK_SIZE"
  fi
  reconcile_group "$VM_BASE_NAME_WK" "$WK_COUNT" "wk" "$WK_CPU" "$WK_RAM" "$WK_DISK" "$wk_extra_size"

  if [[ "$START_VMS" == "true" ]]; then
    start_all_vms

    if [[ "$RUN_BOOTSTRAP" == "true" ]]; then
      if wait_for_talos_api; then
        if bootstrap_cluster; then
          install_cilium
        else
          echo "Bootstrap failed, skipping Cilium installation"
          exit 1
        fi
      else
        echo "Skipping bootstrap due to API timeout"
        exit 1
      fi
    else
      echo "Skipping bootstrap (use --bootstrap flag to enable)"
    fi
  else
    echo "VMs created but not started (use --start-vms flag to start them)"
  fi

  echo "Done. Cluster is ready!"
}

main "$@"