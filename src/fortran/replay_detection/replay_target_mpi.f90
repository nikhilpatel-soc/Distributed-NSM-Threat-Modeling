! replay_target_mpi.f90
!
! 6-rank MPI telemetry sensor/controller with tc-based TX/RX baseline+threat replay.
!
! Rank layout:
!   rank 0 = controller / CSV writer on keyspace
!   rank 1 = worker sensor 1, e.g. collision
!   rank 2 = worker sensor 2, e.g. preimage
!   rank 3 = worker sensor 3, e.g. birthday
!   rank 4 = worker sensor 4, e.g. cipher
!   rank 5 = injector
!
! Traffic model:
!   Worker TX replay:
!       worker_i -> injector
!       worker_i runs persistent sender
!       worker_i shapes only that experiment flow with tc/htb
!
!   Worker RX replay:
!       injector -> worker_i
!       worker_i runs listener
!       injector runs persistent sender to worker_i
!       injector shapes each outbound experiment flow with tc/htb classes
!
! Output format:
!   window,time_seconds,wall_clock_minutes,wall_clock_hhmmss,sensor,class,
!   target_tx,target_rx,target_tx_rate_kbit,target_rx_rate_kbit,
!   delta_tx,delta_rx,activity,direction
!
! Build:
!   mpifort -O2 -std=f2008 -Wall -Wextra replay_target_mpi.f90 -o replay_target_mpi
!
! Default config file:
!   replay_target_mpi_config.nml
!
! Run from keyspace:
!   mpirun --host keyspace,collision,preimage,birthday,cipher,injector -np 6 \
!       ./replay_target_mpi
!
! Notes:
!   tc normally requires root privileges. In MPI mode, use narrow passwordless
!   sudo for tc on the worker nodes and injector, e.g. with visudo:
!
!       cryptlab ALL=(root) NOPASSWD: /usr/sbin/tc, /sbin/tc
!
program replay_target_mpi
    use mpi_f08
    use iso_fortran_env, only: output_unit, error_unit, input_unit
    use, intrinsic :: ieee_exceptions, only: ieee_all, ieee_set_flag
    implicit none

    integer, parameter :: dp = selected_real_kind(12, 100)
    integer, parameter :: i8 = selected_int_kind(18)
    integer, parameter :: max_len = 256
    integer, parameter :: max_workers = 4
    integer, parameter :: controller_rank = 0
    integer, parameter :: injector_rank = 5

    type(MPI_Comm) :: comm
    type(MPI_Status) :: status

    integer :: ierr
    integer :: rank
    integer :: nprocs

    character(len=max_len) :: config_file
    character(len=max_len) :: iface
    character(len=max_len) :: output_file
    character(len=max_len) :: baseline_input
    character(len=max_len) :: threat_signature_input

    character(len=max_len) :: injector_host
    character(len=max_len) :: injector_ip
    character(len=max_len) :: worker_hosts(max_workers)
    character(len=max_len) :: worker_ips(max_workers)

    character(len=max_len) :: sender_log_prefix
    character(len=max_len) :: sender_pid_prefix
    character(len=max_len) :: listener_pid_prefix
    character(len=max_len) :: listener_log_prefix

    character(len=max_len) :: tc_command
    character(len=max_len) :: tc_default_rate
    character(len=max_len) :: tc_burst
    character(len=max_len) :: tc_latency
    character(len=max_len) :: tc_quantum
    character(len=max_len) :: tc_r2q

    character(len=max_len) :: tx_path
    character(len=max_len) :: rx_path
    character(len=max_len) :: sleep_cmd

    logical :: enable_tx_replay
    logical :: enable_rx_replay
    logical :: auto_window_from_threat
    logical :: dry_run
    logical :: require_confirmation
    logical :: overwrite_output
    logical :: abort_on_rate_cap_violation

    integer :: n_workers
    integer :: n_windows
    integer :: window_seconds
    integer :: warmup_windows
    integer :: start_minute
    integer :: baseline_start_window
    integer :: replay_padding_windows
    integer :: tx_port_base
    integer :: rx_port_base

    real(dp) :: baseline_tx_scale
    real(dp) :: baseline_rx_scale
    real(dp) :: min_rate_kbit
    real(dp) :: max_rate_kbit
    real(dp) :: sensor_rate_cap_mbps(max_workers)

    real(dp), allocatable :: baseline_tx(:)
    real(dp), allocatable :: baseline_rx(:)
    real(dp), allocatable :: injector_rx_targets(:,:)

    integer :: window_idx
    integer :: src_rank
    integer :: sensor_id
    integer :: class_id
    integer :: unit_out
    integer :: ios

    integer(i8) :: tx_prev
    integer(i8) :: rx_prev
    integer(i8) :: tx_now
    integer(i8) :: rx_now
    integer(i8) :: dtx_i8
    integer(i8) :: drx_i8

    real(dp) :: packet(6)
    real(dp) :: time_seconds
    real(dp) :: wall_clock_minutes
    character(len=8) :: wall_clock_hhmmss
    real(dp) :: target_tx
    real(dp) :: target_rx
    real(dp) :: target_tx_rate_kbit
    real(dp) :: target_rx_rate_kbit
    real(dp) :: delta_tx
    real(dp) :: delta_rx
    real(dp) :: activity
    real(dp) :: direction

    namelist /replay_target_mpi_config/ &
        iface, output_file, baseline_input, threat_signature_input, &
        n_workers, n_windows, window_seconds, warmup_windows, start_minute, baseline_start_window, &
        auto_window_from_threat, replay_padding_windows, dry_run, require_confirmation, overwrite_output, &
        enable_tx_replay, enable_rx_replay, baseline_tx_scale, baseline_rx_scale, &
        injector_host, injector_ip, worker_hosts, worker_ips, tx_port_base, rx_port_base, &
        sender_log_prefix, sender_pid_prefix, listener_pid_prefix, listener_log_prefix, &
        tc_command, tc_default_rate, tc_burst, tc_latency, tc_quantum, tc_r2q, &
        min_rate_kbit, max_rate_kbit, sensor_rate_cap_mbps, abort_on_rate_cap_violation

    comm = MPI_COMM_WORLD

    call MPI_Init(ierr)
    call MPI_Comm_rank(comm, rank, ierr)
    call MPI_Comm_size(comm, nprocs, ierr)

    call set_defaults()

    if (rank == controller_rank) then
        call get_config_filename(config_file)
        call read_config_file(trim(config_file))
        call validate_config()
        call preflight_controller(trim(config_file), nprocs)
        if (.not. dry_run) call print_run_header(trim(config_file), nprocs)
    end if

    call broadcast_config(comm)

    if (dry_run) then
        if (rank == controller_rank) then
            write(*,*) ''
            write(*,*) 'Dry run complete. No traffic generation was started.'
            flush(output_unit)
        end if
        call MPI_Finalize(ierr)
        call ieee_set_flag(ieee_all, .false.)
        stop 0
    end if

    if (rank == controller_rank) then
        call controller(nprocs, comm)
    else if (rank == injector_rank) then
        call injector(comm)
    else if (rank >= 1 .and. rank <= n_workers) then
        call worker(rank, comm)
    else
        call idle_rank(comm)
    end if

    call MPI_Finalize(ierr)
    call ieee_set_flag(ieee_all, .false.)

contains

    subroutine set_defaults()
        implicit none
        integer :: k

        iface = 'eth0'
        output_file = 'replay_target_telemetry.csv'
        baseline_input = 'baseline.csv'
        threat_signature_input = 'threat_signature_pure.csv'

        n_workers = 4
        n_windows = 12
        window_seconds = 30
        warmup_windows = 1
        start_minute = 0
        baseline_start_window = 1
        auto_window_from_threat = .true.
        replay_padding_windows = 5
        dry_run = .true.
        require_confirmation = .true.
        overwrite_output = .false.

        enable_tx_replay = .true.
        enable_rx_replay = .true.
        baseline_tx_scale = 1.0_dp
        baseline_rx_scale = 1.0_dp

        injector_host = 'injector'
        injector_ip = '10.0.40.16'

        do k = 1, max_workers
            worker_hosts(k) = ''
            worker_ips(k) = ''
        end do

        worker_hosts(1) = 'collision'
        worker_hosts(2) = 'preimage'
        worker_hosts(3) = 'birthday'
        worker_hosts(4) = 'cipher'

        worker_ips(1) = '10.0.40.10'
        worker_ips(2) = '10.0.40.11'
        worker_ips(3) = '10.0.40.12'
        worker_ips(4) = '10.0.40.13'

        tx_port_base = 6001
        rx_port_base = 7001

        sender_log_prefix = '/tmp/tc_sender_rank'
        sender_pid_prefix = '/tmp/tc_sender_rank'
        listener_pid_prefix = '/tmp/tc_listener_rank'
        listener_log_prefix = '/tmp/tc_listener_rank'

        tc_command = 'sudo tc'
        tc_default_rate = '1000mbit'
        tc_burst = '64kbit'
        tc_latency = '400ms'
        tc_quantum = ''
        tc_r2q = '1'

        min_rate_kbit = 8.0_dp
        max_rate_kbit = 1000000.0_dp
        sensor_rate_cap_mbps = 1000.0_dp
        abort_on_rate_cap_violation = .true.
    end subroutine set_defaults


    subroutine get_config_filename(path)
        implicit none
        character(len=*), intent(out) :: path

        if (command_argument_count() >= 1) then
            call get_command_argument(1, path)
        else
            path = 'replay_target_mpi_config.nml'
        end if
    end subroutine get_config_filename


    subroutine read_config_file(path)
        implicit none
        character(len=*), intent(in) :: path
        integer :: unit_cfg
        integer :: ios_local

        unit_cfg = 10
        open(unit=unit_cfg, file=trim(path), status='old', action='read', iostat=ios_local)

        if (ios_local /= 0) then
            write(error_unit,*) 'ERROR: could not open config file: ', trim(path)
            flush(error_unit)
            call MPI_Abort(comm, 1, ierr)
        end if

        read(unit_cfg, nml=replay_target_mpi_config, iostat=ios_local)
        close(unit_cfg)

        if (ios_local /= 0) then
            write(error_unit,*) 'ERROR: could not read /replay_target_mpi_config/ namelist from: ', trim(path)
            flush(error_unit)
            call MPI_Abort(comm, 1, ierr)
        end if
    end subroutine read_config_file


    subroutine validate_config()
        implicit none

        if (n_workers < 1) n_workers = 1
        if (n_workers > max_workers) n_workers = max_workers
        if (n_windows < 1) n_windows = 1
        if (window_seconds < 1) window_seconds = 30
        if (warmup_windows < 0) warmup_windows = 0
        if (start_minute < 0) start_minute = 0
        if (baseline_start_window < 1) baseline_start_window = 1
        if (replay_padding_windows < 0) replay_padding_windows = 0
        if (baseline_tx_scale < 0.0_dp) baseline_tx_scale = 0.0_dp
        if (baseline_rx_scale < 0.0_dp) baseline_rx_scale = 0.0_dp
        if (tx_port_base < 1) tx_port_base = 6001
        if (rx_port_base < 1) rx_port_base = 7001
        if (min_rate_kbit < 1.0_dp) min_rate_kbit = 1.0_dp
        if (max_rate_kbit < min_rate_kbit) max_rate_kbit = min_rate_kbit
        sensor_rate_cap_mbps = max(0.0_dp, sensor_rate_cap_mbps)
    end subroutine validate_config


    subroutine print_run_header(path, nprocs)
        implicit none
        character(len=*), intent(in) :: path
        integer, intent(in) :: nprocs
        integer :: k

        write(*,*) ''
        write(*,*) 'MPI 6-rank TX/RX replay target tc replay'
        write(*,*) '========================================='
        write(*,*) 'Config file              : ', trim(path)
        write(*,*) 'MPI ranks                : ', nprocs
        write(*,*) 'Controller rank          : 0'
        write(*,*) 'Worker ranks             : 1 through ', n_workers
        write(*,*) 'Injector rank            : ', injector_rank
        write(*,*) 'Interface                : ', trim(iface)
        write(*,*) 'Output file              : ', trim(output_file)
        write(*,*) 'Baseline input           : ', trim(baseline_input)
        write(*,*) 'Threat signature input   : ', trim(threat_signature_input)
        write(*,*) 'Replay target            : baseline + threat signature'
        write(*,*) 'Auto-window from threat  : ', auto_window_from_threat
        write(*,*) 'Replay padding windows   : ', replay_padding_windows
        write(*,*) 'Dry run                  : ', dry_run
        write(*,*) 'Windows                  : ', n_windows
        write(*,*) 'Window seconds           : ', window_seconds
        write(*,*) 'Warmup windows           : ', warmup_windows
        write(*,*) 'Start minute             : ', start_minute
        write(*,*) 'Baseline start window    : ', baseline_start_window
        write(*,*) ''
        write(*,*) 'Replay'
        write(*,*) '------'
        write(*,*) 'TX replay enabled        : ', enable_tx_replay
        write(*,*) 'RX replay enabled        : ', enable_rx_replay
        write(*,*) 'TX scale                 : ', baseline_tx_scale
        write(*,*) 'RX scale                 : ', baseline_rx_scale
        write(*,*) 'Injector host/IP         : ', trim(injector_host), ' / ', trim(injector_ip)
        write(*,*) 'TX port base             : ', tx_port_base
        write(*,*) 'RX port base             : ', rx_port_base
        do k = 1, n_workers
            write(*,'("Worker ",I0,": ",A," / ",A)') k, trim(worker_hosts(k)), trim(worker_ips(k))
        end do
        write(*,*) ''
        write(*,*) 'tc settings'
        write(*,*) '-----------'
        write(*,*) 'tc command               : ', trim(tc_command)
        write(*,*) 'tc default rate          : ', trim(tc_default_rate)
        write(*,*) 'tc burst                 : ', trim(tc_burst)
        write(*,*) 'tc latency               : ', trim(tc_latency)
        write(*,*) 'tc quantum               : ', trim(tc_quantum)
        write(*,*) 'tc r2q                   : ', trim(tc_r2q)
        write(*,*) 'min rate kbit            : ', min_rate_kbit
        write(*,*) 'max rate kbit            : ', max_rate_kbit
        write(*,*) ''
        flush(output_unit)
    end subroutine print_run_header


    subroutine broadcast_config(comm)
        implicit none
        type(MPI_Comm), intent(in) :: comm
        integer :: ierr_local

        call MPI_Bcast(iface, len(iface), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(output_file, len(output_file), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(baseline_input, len(baseline_input), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(threat_signature_input, len(threat_signature_input), MPI_CHARACTER, controller_rank, comm, ierr_local)

        call MPI_Bcast(n_workers, 1, MPI_INTEGER, controller_rank, comm, ierr_local)
        call MPI_Bcast(n_windows, 1, MPI_INTEGER, controller_rank, comm, ierr_local)
        call MPI_Bcast(window_seconds, 1, MPI_INTEGER, controller_rank, comm, ierr_local)
        call MPI_Bcast(warmup_windows, 1, MPI_INTEGER, controller_rank, comm, ierr_local)
        call MPI_Bcast(start_minute, 1, MPI_INTEGER, controller_rank, comm, ierr_local)
        call MPI_Bcast(baseline_start_window, 1, MPI_INTEGER, controller_rank, comm, ierr_local)
        call MPI_Bcast(replay_padding_windows, 1, MPI_INTEGER, controller_rank, comm, ierr_local)
        call MPI_Bcast(auto_window_from_threat, 1, MPI_LOGICAL, controller_rank, comm, ierr_local)
        call MPI_Bcast(dry_run, 1, MPI_LOGICAL, controller_rank, comm, ierr_local)
        call MPI_Bcast(require_confirmation, 1, MPI_LOGICAL, controller_rank, comm, ierr_local)
        call MPI_Bcast(overwrite_output, 1, MPI_LOGICAL, controller_rank, comm, ierr_local)

        call MPI_Bcast(enable_tx_replay, 1, MPI_LOGICAL, controller_rank, comm, ierr_local)
        call MPI_Bcast(enable_rx_replay, 1, MPI_LOGICAL, controller_rank, comm, ierr_local)
        call MPI_Bcast(baseline_tx_scale, 1, MPI_DOUBLE_PRECISION, controller_rank, comm, ierr_local)
        call MPI_Bcast(baseline_rx_scale, 1, MPI_DOUBLE_PRECISION, controller_rank, comm, ierr_local)

        call MPI_Bcast(injector_host, len(injector_host), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(injector_ip, len(injector_ip), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(worker_hosts, max_workers * max_len, MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(worker_ips, max_workers * max_len, MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(tx_port_base, 1, MPI_INTEGER, controller_rank, comm, ierr_local)
        call MPI_Bcast(rx_port_base, 1, MPI_INTEGER, controller_rank, comm, ierr_local)

        call MPI_Bcast(sender_log_prefix, len(sender_log_prefix), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(sender_pid_prefix, len(sender_pid_prefix), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(listener_pid_prefix, len(listener_pid_prefix), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(listener_log_prefix, len(listener_log_prefix), MPI_CHARACTER, controller_rank, comm, ierr_local)

        call MPI_Bcast(tc_command, len(tc_command), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(tc_default_rate, len(tc_default_rate), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(tc_burst, len(tc_burst), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(tc_latency, len(tc_latency), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(tc_quantum, len(tc_quantum), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(tc_r2q, len(tc_r2q), MPI_CHARACTER, controller_rank, comm, ierr_local)
        call MPI_Bcast(min_rate_kbit, 1, MPI_DOUBLE_PRECISION, controller_rank, comm, ierr_local)
        call MPI_Bcast(max_rate_kbit, 1, MPI_DOUBLE_PRECISION, controller_rank, comm, ierr_local)
        call MPI_Bcast(sensor_rate_cap_mbps, max_workers, MPI_DOUBLE_PRECISION, controller_rank, comm, ierr_local)
        call MPI_Bcast(abort_on_rate_cap_violation, 1, MPI_LOGICAL, controller_rank, comm, ierr_local)
    end subroutine broadcast_config


    subroutine controller(nprocs, comm)
        implicit none
        integer, intent(in) :: nprocs
        type(MPI_Comm), intent(in) :: comm
        integer :: ierr_local

        if (nprocs < injector_rank + 1) then
            write(error_unit,*) 'ERROR: this design requires at least 6 MPI ranks.'
            flush(error_unit)
            call MPI_Abort(comm, 1, ierr_local)
        end if

        unit_out = 20

        call confirm_output_overwrite_if_needed(trim(output_file))

        write(*,*) 'Preparing to write output file: ', trim(output_file)
        flush(output_unit)

        open(unit=unit_out, file=trim(output_file), status='replace', action='write', iostat=ios)

        if (ios /= 0) then
            write(error_unit,*) 'ERROR: could not open output file: ', trim(output_file)
            flush(error_unit)
            call MPI_Abort(comm, 1, ierr_local)
        end if

        write(unit_out,'(A)') 'window,time_seconds,wall_clock_minutes,wall_clock_hhmmss,' // &
            'sensor,class,target_tx,target_rx,target_tx_rate_kbit,target_rx_rate_kbit,' // &
            'delta_tx,delta_rx,activity,direction'
        flush(unit_out)

        call MPI_Barrier(comm, ierr_local)

        do window_idx = 1, n_windows
            time_seconds = real((window_idx - 1) * window_seconds, dp)
            wall_clock_minutes = real(start_minute, dp) + time_seconds / 60.0_dp
            wall_clock_hhmmss = wall_clock_string(start_minute, time_seconds)
            class_id = reporting_class(start_minute + int(time_seconds / 60.0_dp))

            do src_rank = 1, n_workers
                call MPI_Recv(packet, 6, MPI_DOUBLE_PRECISION, src_rank, window_idx, &
                              comm, status, ierr_local)

                sensor_id = src_rank
                target_tx = packet(1)
                target_rx = packet(2)
                target_tx_rate_kbit = packet(3)
                target_rx_rate_kbit = packet(4)
                delta_tx = packet(5)
                delta_rx = packet(6)

                activity = delta_tx + delta_rx

                if (activity > 0.0_dp) then
                    direction = (delta_tx - delta_rx) / activity
                else
                    direction = 0.0_dp
                end if

                write(unit_out,'(I0,",",G0,",",G0,",",A,",",I0,",",I0,' // &
                    '",",G0,",",G0,",",G0,",",G0,",",G0,",",G0,",",G0,",",G0)') &
                    window_idx, time_seconds, wall_clock_minutes, trim(wall_clock_hhmmss), &
                    sensor_id, class_id, target_tx, target_rx, target_tx_rate_kbit, target_rx_rate_kbit, &
                    delta_tx, delta_rx, activity, direction
            end do

            flush(unit_out)
            write(*,'("window ",I0,"/",I0," complete")') window_idx, n_windows
            flush(output_unit)
        end do

        call write_replay_metadata(unit_out)
        close(unit_out)

        call MPI_Barrier(comm, ierr_local)

        write(*,*) ''
        write(*,*) 'Done.'
        write(*,*) 'Wrote: ', trim(output_file)
        flush(output_unit)
    end subroutine controller


    subroutine worker(rank, comm)
        implicit none
        integer, intent(in) :: rank
        type(MPI_Comm), intent(in) :: comm
        integer :: ierr_local

        allocate(baseline_tx(n_windows))
        allocate(baseline_rx(n_windows))
        baseline_tx = 0.0_dp
        baseline_rx = 0.0_dp

        call read_baseline_for_sensor(trim(baseline_input), rank, baseline_tx, baseline_rx)
        call add_threat_signature_for_sensor(trim(threat_signature_input), rank, baseline_tx, baseline_rx)

        tx_path = '/sys/class/net/' // trim(iface) // '/statistics/tx_bytes'
        rx_path = '/sys/class/net/' // trim(iface) // '/statistics/rx_bytes'

        if (enable_tx_replay) then
            call setup_worker_tx_tc(rank)
        end if

        if (enable_rx_replay) then
            call start_listener(rank, rx_port_base + rank - 1)
        end if

        call MPI_Barrier(comm, ierr_local)

        if (enable_tx_replay) then
            call start_sender(rank, injector_host, tx_port_base + rank - 1)
        end if

        call run_worker_warmup(rank)

        call read_counter(trim(tx_path), tx_prev)
        call read_counter(trim(rx_path), rx_prev)

        do window_idx = 1, n_windows
            target_tx = baseline_tx_scale * baseline_tx(window_idx)
            target_rx = baseline_rx_scale * baseline_rx(window_idx)

            target_tx_rate_kbit = clamp_rate(bytes_per_window_to_kbit(target_tx, window_seconds))
            target_rx_rate_kbit = clamp_rate(bytes_per_window_to_kbit(target_rx, window_seconds))

            if (enable_tx_replay) then
                call change_worker_tx_rate(rank, target_tx_rate_kbit)
            end if

            write(sleep_cmd,'("sleep ",I0)') window_seconds
            call execute_command_line(trim(sleep_cmd))

            call read_counter(trim(tx_path), tx_now)
            call read_counter(trim(rx_path), rx_now)

            dtx_i8 = tx_now - tx_prev
            drx_i8 = rx_now - rx_prev

            if (dtx_i8 < 0_i8) dtx_i8 = 0_i8
            if (drx_i8 < 0_i8) drx_i8 = 0_i8

            packet(1) = target_tx
            packet(2) = target_rx
            packet(3) = target_tx_rate_kbit
            packet(4) = target_rx_rate_kbit
            packet(5) = real(dtx_i8, dp)
            packet(6) = real(drx_i8, dp)

            call MPI_Send(packet, 6, MPI_DOUBLE_PRECISION, controller_rank, window_idx, comm, ierr_local)

            tx_prev = tx_now
            rx_prev = rx_now
        end do

        call cleanup_worker(rank)

        deallocate(baseline_tx)
        deallocate(baseline_rx)

        call MPI_Barrier(comm, ierr_local)

        write(*,'("rank ",I0," worker complete")') rank
        flush(output_unit)
    end subroutine worker



    subroutine run_worker_warmup(rank)
        implicit none
        integer, intent(in) :: rank
        integer :: warm_idx

        if (warmup_windows <= 0) return

        do warm_idx = 1, warmup_windows
            target_tx = baseline_tx_scale * baseline_tx(1)
            target_tx_rate_kbit = clamp_rate(bytes_per_window_to_kbit(target_tx, window_seconds))

            if (enable_tx_replay) then
                call change_worker_tx_rate(rank, target_tx_rate_kbit)
            end if

            write(sleep_cmd,'("sleep ",I0)') window_seconds
            call execute_command_line(trim(sleep_cmd))
        end do

        write(*,'("rank ",I0," warmup complete: ",I0," window(s)")') rank, warmup_windows
        flush(output_unit)
    end subroutine run_worker_warmup


    subroutine injector(comm)
        implicit none
        type(MPI_Comm), intent(in) :: comm
        integer :: ierr_local
        integer :: k
        real(dp) :: rate_kbit

        allocate(injector_rx_targets(n_windows, n_workers))
        injector_rx_targets = 0.0_dp

        if (enable_rx_replay) then
            call read_all_replay_target_rx(trim(baseline_input), trim(threat_signature_input), injector_rx_targets)
            call setup_injector_rx_tc()
        end if

        if (enable_tx_replay) then
            do k = 1, n_workers
                call start_listener(injector_rank, tx_port_base + k - 1)
            end do
        end if

        call MPI_Barrier(comm, ierr_local)

        if (enable_rx_replay) then
            do k = 1, n_workers
                call start_sender(injector_rank + k, worker_hosts(k), rx_port_base + k - 1)
            end do
        end if

        call run_injector_warmup()

        do window_idx = 1, n_windows
            if (enable_rx_replay) then
                do k = 1, n_workers
                    rate_kbit = clamp_rate(bytes_per_window_to_kbit( &
                        baseline_rx_scale * injector_rx_targets(window_idx, k), window_seconds))
                    call change_injector_rx_rate(k, rate_kbit)
                end do
            end if

            write(sleep_cmd,'("sleep ",I0)') window_seconds
            call execute_command_line(trim(sleep_cmd))
        end do

        call cleanup_injector()

        if (allocated(injector_rx_targets)) deallocate(injector_rx_targets)

        call MPI_Barrier(comm, ierr_local)

        write(*,*) 'rank 5 injector complete'
        flush(output_unit)
    end subroutine injector



    subroutine run_injector_warmup()
        implicit none
        integer :: warm_idx
        integer :: k
        real(dp) :: rate_kbit

        if (warmup_windows <= 0) return

        do warm_idx = 1, warmup_windows
            if (enable_rx_replay) then
                do k = 1, n_workers
                    rate_kbit = clamp_rate(bytes_per_window_to_kbit( &
                        baseline_rx_scale * injector_rx_targets(1, k), window_seconds))
                    call change_injector_rx_rate(k, rate_kbit)
                end do
            end if

            write(sleep_cmd,'("sleep ",I0)') window_seconds
            call execute_command_line(trim(sleep_cmd))
        end do

        write(*,'("rank 5 injector warmup complete: ",I0," window(s)")') warmup_windows
        flush(output_unit)
    end subroutine run_injector_warmup


    subroutine idle_rank(comm)
        implicit none
        type(MPI_Comm), intent(in) :: comm
        integer :: ierr_local

        call MPI_Barrier(comm, ierr_local)
        call MPI_Barrier(comm, ierr_local)
    end subroutine idle_rank


    real(dp) function bytes_per_window_to_kbit(bytes, seconds)
        implicit none
        real(dp), intent(in) :: bytes
        integer, intent(in) :: seconds

        if (seconds <= 0) then
            bytes_per_window_to_kbit = min_rate_kbit
        else
            bytes_per_window_to_kbit = 8.0_dp * bytes / real(seconds, dp) / 1000.0_dp
        end if
    end function bytes_per_window_to_kbit


    real(dp) function clamp_rate(rate_kbit)
        implicit none
        real(dp), intent(in) :: rate_kbit

        clamp_rate = max(min_rate_kbit, rate_kbit)
        clamp_rate = min(max_rate_kbit, clamp_rate)
    end function clamp_rate


    character(len=64) function rate_string(rate_kbit)
        implicit none
        real(dp), intent(in) :: rate_kbit
        integer(i8) :: rounded

        rounded = max(1_i8, nint(rate_kbit, kind=i8))
        write(rate_string,'(I0,"kbit")') rounded
    end function rate_string


    character(len=64) function classid_string(worker_index)
        implicit none
        integer, intent(in) :: worker_index
        write(classid_string,'("1:",I0)') 10 + worker_index
    end function classid_string


    subroutine setup_worker_tx_tc(worker_rank)
        implicit none
        integer, intent(in) :: worker_rank
        character(len=2048) :: cmd
        character(len=64) :: port_string

        write(port_string,'(I0)') tx_port_base + worker_rank - 1

        call tc_delete_root()

        cmd = trim(tc_command) // ' qdisc add dev ' // trim(iface) // ' root handle 1: htb r2q ' // trim(tc_r2q)
        call run_tc_or_abort(cmd, 'worker add htb root', worker_rank)

        cmd = trim(tc_command) // ' class add dev ' // trim(iface) // ' parent 1: classid 1:10 htb rate ' // &
              trim(rate_string(min_rate_kbit)) // ' ceil ' // trim(rate_string(min_rate_kbit))
        call run_tc_or_abort(cmd, 'worker add experiment class', worker_rank)

        cmd = trim(tc_command) // ' filter add dev ' // trim(iface) // &
              ' protocol ip parent 1: prio 1 u32 match ip protocol 6 0xff match ip dst ' // &
              trim(injector_ip) // '/32 match ip dport ' // trim(port_string) // ' 0xffff flowid 1:10'
        call run_tc_or_abort(cmd, 'worker add experiment filter', worker_rank)
    end subroutine setup_worker_tx_tc


    subroutine change_worker_tx_rate(worker_rank, rate_kbit)
        implicit none
        integer, intent(in) :: worker_rank
        real(dp), intent(in) :: rate_kbit
        character(len=2048) :: cmd

        cmd = trim(tc_command) // ' class change dev ' // trim(iface) // ' parent 1: classid 1:10 htb rate ' // &
              trim(rate_string(rate_kbit)) // ' ceil ' // trim(rate_string(rate_kbit))
        call run_tc_or_abort(cmd, 'worker change TX class rate', worker_rank)
    end subroutine change_worker_tx_rate


    subroutine setup_injector_rx_tc()
        implicit none
        character(len=2048) :: cmd
        character(len=64) :: port_string
        integer :: k

        call tc_delete_root()

        cmd = trim(tc_command) // ' qdisc add dev ' // trim(iface) // ' root handle 1: htb r2q ' // trim(tc_r2q)
        call run_tc_or_abort(cmd, 'injector add htb root', injector_rank)

        do k = 1, n_workers
            write(port_string,'(I0)') rx_port_base + k - 1

            cmd = trim(tc_command) // ' class add dev ' // trim(iface) // ' parent 1: classid ' // &
                  trim(classid_string(k)) // ' htb rate ' // trim(rate_string(min_rate_kbit)) // &
                  ' ceil ' // trim(rate_string(min_rate_kbit))
            call run_tc_or_abort(cmd, 'injector add RX class', injector_rank)

            cmd = trim(tc_command) // ' filter add dev ' // trim(iface) // &
                  ' protocol ip parent 1: prio ' // trim(int_string(k)) // &
                  ' u32 match ip protocol 6 0xff match ip dst ' // trim(worker_ips(k)) // &
                  '/32 match ip dport ' // trim(port_string) // ' 0xffff flowid ' // trim(classid_string(k))
            call run_tc_or_abort(cmd, 'injector add RX filter', injector_rank)
        end do
    end subroutine setup_injector_rx_tc


    subroutine change_injector_rx_rate(worker_index, rate_kbit)
        implicit none
        integer, intent(in) :: worker_index
        real(dp), intent(in) :: rate_kbit
        character(len=2048) :: cmd

        cmd = trim(tc_command) // ' class change dev ' // trim(iface) // ' parent 1: classid ' // &
              trim(classid_string(worker_index)) // ' htb rate ' // trim(rate_string(rate_kbit)) // &
              ' ceil ' // trim(rate_string(rate_kbit))
        call run_tc_or_abort(cmd, 'injector change RX class rate', injector_rank)
    end subroutine change_injector_rx_rate


    character(len=32) function int_string(value)
        implicit none
        integer, intent(in) :: value
        write(int_string,'(I0)') value
    end function int_string


    subroutine tc_delete_root()
        implicit none
        character(len=2048) :: cmd

        cmd = trim(tc_command) // ' qdisc del dev ' // trim(iface) // ' root > /dev/null 2>&1'
        call execute_command_line(trim(cmd))
    end subroutine tc_delete_root


    subroutine run_tc_or_abort(cmd, label, who)
        implicit none
        character(len=*), intent(in) :: cmd
        character(len=*), intent(in) :: label
        integer, intent(in) :: who
        integer :: exit_code

        call execute_command_line(trim(cmd), exitstat=exit_code)

        if (exit_code /= 0) then
            write(error_unit,*) 'ERROR: rank ', who, ' tc failure: ', trim(label)
            write(error_unit,*) trim(cmd)
            flush(error_unit)
            call cleanup_all_local()
            call MPI_Abort(comm, 1, ierr)
        end if
    end subroutine run_tc_or_abort


    subroutine start_sender(id, host, port)
        implicit none
        integer, intent(in) :: id
        character(len=*), intent(in) :: host
        integer, intent(in) :: port
        character(len=2048) :: cmd
        character(len=64) :: port_string
        character(len=512) :: log_file
        character(len=512) :: pid_file
        integer :: exit_code

        write(port_string,'(I0)') port
        write(log_file,'(A,I0,A)') trim(sender_log_prefix), id, '.log'
        write(pid_file,'(A,I0,A)') trim(sender_pid_prefix), id, '.pid'

        cmd = 'sh -c "cat /dev/zero | nc ' // trim(host) // ' ' // trim(port_string) // &
              ' > ' // trim(log_file) // ' 2>&1 & echo $! > ' // trim(pid_file) // '"'

        call execute_command_line(trim(cmd), exitstat=exit_code)

        if (exit_code /= 0) then
            write(error_unit,*) 'ERROR: rank ', rank, ' failed to start sender.'
            write(error_unit,*) trim(cmd)
            flush(error_unit)
            call cleanup_all_local()
            call MPI_Abort(comm, 1, ierr)
        end if
    end subroutine start_sender


    subroutine start_listener(id, port)
        implicit none
        integer, intent(in) :: id
        integer, intent(in) :: port
        character(len=2048) :: cmd
        character(len=64) :: port_string
        character(len=512) :: log_file
        character(len=512) :: pid_file
        integer :: exit_code

        write(port_string,'(I0)') port
        write(log_file,'(A,I0,A,A,A)') trim(listener_log_prefix), id, '_', trim(port_string), '.log'
        write(pid_file,'(A,I0,A,A,A)') trim(listener_pid_prefix), id, '_', trim(port_string), '.pid'

        cmd = 'sh -c "nc -l -p ' // trim(port_string) // ' > /dev/null 2> ' // trim(log_file) // &
              ' & echo $! > ' // trim(pid_file) // '"'

        call execute_command_line(trim(cmd), exitstat=exit_code)

        if (exit_code /= 0) then
            write(error_unit,*) 'ERROR: rank ', rank, ' failed to start listener.'
            write(error_unit,*) trim(cmd)
            flush(error_unit)
            call cleanup_all_local()
            call MPI_Abort(comm, 1, ierr)
        end if
    end subroutine start_listener


    subroutine cleanup_worker(worker_rank)
        implicit none
        integer, intent(in) :: worker_rank

        call kill_pid_file(sender_pid_prefix, worker_rank)
        call kill_pid_file(listener_pid_prefix, worker_rank)
        call cleanup_all_local()
    end subroutine cleanup_worker


    subroutine cleanup_injector()
        implicit none
        integer :: k
        integer :: id

        do k = 1, n_workers
            call kill_pid_file(listener_pid_prefix, injector_rank, tx_port_base + k - 1)
        end do

        do k = 1, n_workers
            id = injector_rank + k
            call kill_pid_file(sender_pid_prefix, id)
        end do

        call cleanup_all_local()
    end subroutine cleanup_injector


    subroutine cleanup_all_local()
        implicit none
        character(len=2048) :: cmd

        cmd = trim(tc_command) // ' qdisc del dev ' // trim(iface) // ' root > /dev/null 2>&1'
        call execute_command_line(trim(cmd))

        ! Safety cleanup for nc processes owned by this account on this node.
        ! This should be acceptable during these controlled lab runs.
        cmd = 'pkill -u "$USER" nc > /dev/null 2>&1 || true'
        call execute_command_line(trim(cmd))
    end subroutine cleanup_all_local


    subroutine kill_pid_file(prefix, id, port)
        implicit none
        character(len=*), intent(in) :: prefix
        integer, intent(in) :: id
        integer, intent(in), optional :: port
        character(len=512) :: pid_file
        character(len=2048) :: cmd

        if (present(port)) then
            write(pid_file,'(A,I0,A,I0,A)') trim(prefix), id, '_', port, '.pid'
        else
            write(pid_file,'(A,I0,A)') trim(prefix), id, '.pid'
        end if

        cmd = 'sh -c ''pid=""; ' // &
              'if [ -f ' // trim(pid_file) // ' ]; then ' // &
              'pid=$(cat ' // trim(pid_file) // ' 2>/dev/null || true); ' // &
              'if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi; ' // &
              'rm -f ' // trim(pid_file) // '; ' // &
              'fi'''

        call execute_command_line(trim(cmd))
    end subroutine kill_pid_file



    subroutine abort_with_message(message)
        implicit none
        character(len=*), intent(in) :: message
        write(error_unit,*) 'ERROR: ', trim(message)
        flush(error_unit)
        call MPI_Abort(comm, 1, ierr)
    end subroutine abort_with_message


    logical function file_contains_text(path, needle)
        implicit none
        character(len=*), intent(in) :: path
        character(len=*), intent(in) :: needle
        integer :: unit_num, ios_local
        character(len=4096) :: line

        file_contains_text = .false.
        unit_num = 81
        open(unit=unit_num, file=trim(path), status='old', action='read', iostat=ios_local)
        if (ios_local /= 0) return

        do
            read(unit_num,'(A)',iostat=ios_local) line
            if (ios_local /= 0) exit
            if (index(line, trim(needle)) > 0) then
                file_contains_text = .true.
                exit
            end if
        end do
        close(unit_num)
    end function file_contains_text


    subroutine validate_standard_input(path, begin_marker, label)
        implicit none
        character(len=*), intent(in) :: path
        character(len=*), intent(in) :: begin_marker
        character(len=*), intent(in) :: label
        integer :: unit_num, ios_local
        character(len=4096) :: line
        logical :: found_marker

        unit_num = 82
        open(unit=unit_num, file=trim(path), status='old', action='read', iostat=ios_local)
        if (ios_local /= 0) call abort_with_message('could not open ' // trim(label) // ' file: ' // trim(path))

        read(unit_num,'(A)',iostat=ios_local) line
        if (ios_local /= 0) call abort_with_message('could not read header from ' // trim(label) // ' file: ' // trim(path))
        if (trim(line) /= 'window,time_seconds,sensor,class,delta_tx,delta_rx,activity,direction') then
            call abort_with_message('unexpected CSV header in ' // trim(label) // ' file: ' // trim(path))
        end if

        found_marker = .false.
        do
            read(unit_num,'(A)',iostat=ios_local) line
            if (ios_local /= 0) exit
            if (index(line, trim(begin_marker)) > 0) then
                found_marker = .true.
                exit
            end if
        end do
        close(unit_num)

        if (.not. found_marker) then
            call abort_with_message('metadata delimiter missing in ' // trim(label) // ' file: ' // trim(begin_marker))
        end if

        if (.not. file_contains_text(path, '"delta_tx_unit": "bytes_per_window"')) then
            call abort_with_message('delta_tx unit is not bytes_per_window in ' // trim(label) // ' file')
        end if
        if (.not. file_contains_text(path, '"delta_rx_unit": "bytes_per_window"')) then
            call abort_with_message('delta_rx unit is not bytes_per_window in ' // trim(label) // ' file')
        end if
    end subroutine validate_standard_input


    subroutine get_csv_range(path, begin_marker, min_win, max_win, min_t, max_t, row_count)
        implicit none
        character(len=*), intent(in) :: path
        character(len=*), intent(in) :: begin_marker
        integer, intent(out) :: min_win, max_win, row_count
        real(dp), intent(out) :: min_t, max_t
        integer :: unit_num, ios_local, win, sensor, cls
        real(dp) :: tsec, tx, rx, act, dir
        character(len=4096) :: line
        logical :: ok, first

        min_win = huge(1)
        max_win = -huge(1)
        min_t = huge(1.0_dp)
        max_t = -huge(1.0_dp)
        row_count = 0
        first = .true.

        unit_num = 83
        open(unit=unit_num, file=trim(path), status='old', action='read', iostat=ios_local)
        if (ios_local /= 0) call abort_with_message('could not open CSV file: ' // trim(path))
        read(unit_num,'(A)',iostat=ios_local) line

        do
            read(unit_num,'(A)',iostat=ios_local) line
            if (ios_local /= 0) exit
            if (len_trim(line) == 0) cycle
            if (index(line, trim(begin_marker)) > 0) exit

            call parse_telemetry_line(line, win, tsec, sensor, cls, tx, rx, act, dir, ok)
            if (.not. ok) call abort_with_message('malformed CSV data row in: ' // trim(path))

            row_count = row_count + 1
            if (first) then
                min_win = win
                max_win = win
                min_t = tsec
                max_t = tsec
                first = .false.
            else
                min_win = min(min_win, win)
                max_win = max(max_win, win)
                min_t = min(min_t, tsec)
                max_t = max(max_t, tsec)
            end if
        end do
        close(unit_num)

        if (row_count <= 0) call abort_with_message('no CSV data rows found in: ' // trim(path))
    end subroutine get_csv_range


    subroutine load_standard_csv(path, begin_marker, max_win, n_sensors_local, times, classes, tx, rx, seen)
        implicit none
        character(len=*), intent(in) :: path
        character(len=*), intent(in) :: begin_marker
        integer, intent(in) :: max_win
        integer, intent(in) :: n_sensors_local
        real(dp), intent(out) :: times(:,:)
        integer, intent(out) :: classes(:,:)
        real(dp), intent(out) :: tx(:,:)
        real(dp), intent(out) :: rx(:,:)
        logical, intent(out) :: seen(:,:)
        integer :: unit_num, ios_local, win, sensor, cls
        real(dp) :: tsec, txv, rxv, act, dir
        character(len=4096) :: line
        logical :: ok

        times = 0.0_dp
        classes = 0
        tx = 0.0_dp
        rx = 0.0_dp
        seen = .false.

        unit_num = 84
        open(unit=unit_num, file=trim(path), status='old', action='read', iostat=ios_local)
        if (ios_local /= 0) call abort_with_message('could not open CSV file: ' // trim(path))
        read(unit_num,'(A)',iostat=ios_local) line

        do
            read(unit_num,'(A)',iostat=ios_local) line
            if (ios_local /= 0) exit
            if (len_trim(line) == 0) cycle
            if (index(line, trim(begin_marker)) > 0) exit

            call parse_telemetry_line(line, win, tsec, sensor, cls, txv, rxv, act, dir, ok)
            if (.not. ok) call abort_with_message('malformed CSV data row in: ' // trim(path))
            if (win < 1 .or. win > max_win) call abort_with_message('window out of range in: ' // trim(path))
            if (sensor < 1 .or. sensor > n_sensors_local) cycle
            if (seen(win, sensor)) call abort_with_message('duplicate window/sensor row in: ' // trim(path))

            times(win, sensor) = tsec
            classes(win, sensor) = cls
            tx(win, sensor) = txv
            rx(win, sensor) = rxv
            seen(win, sensor) = .true.
        end do
        close(unit_num)
    end subroutine load_standard_csv


    integer function extract_int_json(line, key)
        implicit none
        character(len=*), intent(in) :: line
        character(len=*), intent(in) :: key
        integer :: pos, start_pos, end_pos, ios_local
        character(len=128) :: token

        extract_int_json = 0
        pos = index(line, trim(key))
        if (pos <= 0) return
        start_pos = pos + len_trim(key)
        do while (start_pos <= len_trim(line))
            if (line(start_pos:start_pos) /= ' ' .and. line(start_pos:start_pos) /= ':') exit
            start_pos = start_pos + 1
        end do
        end_pos = start_pos
        do while (end_pos <= len_trim(line))
            if (line(end_pos:end_pos) == ',' .or. line(end_pos:end_pos) == '}') exit
            end_pos = end_pos + 1
        end do
        token = adjustl(line(start_pos:end_pos-1))
        read(token, *, iostat=ios_local) extract_int_json
        if (ios_local /= 0) extract_int_json = 0
    end function extract_int_json


    real(dp) function extract_real_json(line, key)
        implicit none
        character(len=*), intent(in) :: line
        character(len=*), intent(in) :: key
        integer :: pos, start_pos, end_pos, ios_local
        character(len=128) :: token

        extract_real_json = 0.0_dp
        pos = index(line, trim(key))
        if (pos <= 0) return
        start_pos = pos + len_trim(key)
        do while (start_pos <= len_trim(line))
            if (line(start_pos:start_pos) /= ' ' .and. line(start_pos:start_pos) /= ':') exit
            start_pos = start_pos + 1
        end do
        end_pos = start_pos
        do while (end_pos <= len_trim(line))
            if (line(end_pos:end_pos) == ',' .or. line(end_pos:end_pos) == '}') exit
            end_pos = end_pos + 1
        end do
        token = adjustl(line(start_pos:end_pos-1))
        read(token, *, iostat=ios_local) extract_real_json
        if (ios_local /= 0) extract_real_json = 0.0_dp
    end function extract_real_json


    subroutine print_threat_metadata_table(path)
        implicit none
        character(len=*), intent(in) :: path
        integer :: unit_num, ios_local
        character(len=4096) :: line
        logical :: in_meta
        integer :: threat_id, sensor, start_win, end_win, ramp_windows, n_found
        real(dp) :: tx_mbps, rx_mbps
        character(len=8) :: start_text, stop_text
        real(dp) :: tx_bytes, rx_bytes

        unit_num = 85
        open(unit=unit_num, file=trim(path), status='old', action='read', iostat=ios_local)
        if (ios_local /= 0) call abort_with_message('could not open threat file for metadata table: ' // trim(path))

        write(*,*) ''
        write(*,*) 'Detected threat signatures:'
        write(*,*) ''
        write(*,'(A)') 'ID  Sensor  Start Time  Stop Time   TX Mbps  TX Bytes/Window  RX Mbps  RX Bytes/Window'
        write(*,'(A)') '--  ------  ----------  ---------   -------  ---------------  -------  ---------------'

        in_meta = .false.
        n_found = 0
        do
            read(unit_num,'(A)',iostat=ios_local) line
            if (ios_local /= 0) exit
            if (index(line, '__THREAT_SIGNATURE_METADATA_JSON_BEGIN__') > 0) then
                in_meta = .true.
                cycle
            end if
            if (index(line, '__THREAT_SIGNATURE_METADATA_JSON_END__') > 0) exit
            if (.not. in_meta) cycle
            if (index(line, '"threat":') <= 0) cycle

            threat_id = extract_int_json(line, '"threat"')
            sensor = extract_int_json(line, '"sensor"')
            start_win = extract_int_json(line, '"start_window"')
            end_win = extract_int_json(line, '"end_window"')
            ramp_windows = extract_int_json(line, '"ramp_windows"')
            tx_mbps = extract_real_json(line, '"tx_mbps"')
            rx_mbps = extract_real_json(line, '"rx_mbps"')

            start_text = clock_from_seconds(real((start_win - 1) * window_seconds, dp))
            stop_text = clock_from_seconds(real((end_win - 1) * window_seconds, dp))
            tx_bytes = tx_mbps * 1.0e6_dp * real(window_seconds, dp) / 8.0_dp
            rx_bytes = rx_mbps * 1.0e6_dp * real(window_seconds, dp) / 8.0_dp

            write(*,'(I2,2X,I6,2X,A10,2X,A9,3X,F7.1,2X,F15.0,2X,F7.1,2X,F15.0)') &
                threat_id, sensor, trim(start_text), trim(stop_text), tx_mbps, tx_bytes, rx_mbps, rx_bytes
            n_found = n_found + 1
        end do
        close(unit_num)

        if (n_found == 0) then
            write(*,*) 'WARNING: no individual threat metadata rows were found.'
        end if
        flush(output_unit)
    end subroutine print_threat_metadata_table


    subroutine preflight_controller(path, nprocs)
        implicit none
        character(len=*), intent(in) :: path
        integer, intent(in) :: nprocs
        integer :: b_min_win, b_max_win, b_rows
        integer :: t_min_win, t_max_win, t_rows
        real(dp) :: b_min_t, b_max_t, t_min_t, t_max_t
        real(dp), allocatable :: b_time(:,:), t_time(:,:), b_tx(:,:), b_rx(:,:), t_tx(:,:), t_rx(:,:)
        integer, allocatable :: b_cls(:,:), t_cls(:,:)
        logical, allocatable :: b_seen(:,:), t_seen(:,:)
        integer :: w, s, active_start, active_end, replay_start, replay_end
        logical :: found_active
        real(dp) :: tx_mbps, rx_mbps
        real(dp) :: tx_min(max_workers), tx_max(max_workers), rx_min(max_workers), rx_max(max_workers)
        character(len=16) :: answer

        if (nprocs < injector_rank + 1) then
            call abort_with_message('this design requires at least 6 MPI ranks')
        end if

        call validate_standard_input(trim(baseline_input), '__BASELINE_METADATA_JSON_BEGIN__', 'baseline')
        call validate_standard_input(trim(threat_signature_input), '__THREAT_SIGNATURE_METADATA_JSON_BEGIN__', 'threat signature')

        call get_csv_range(trim(baseline_input), '__BASELINE_METADATA_JSON_BEGIN__', b_min_win, b_max_win, b_min_t, b_max_t, b_rows)
        call get_csv_range(trim(threat_signature_input), '__THREAT_SIGNATURE_METADATA_JSON_BEGIN__', t_min_win, t_max_win, t_min_t, t_max_t, t_rows)

        if (b_min_win /= t_min_win .or. b_max_win /= t_max_win) then
            call abort_with_message('baseline and threat signature window ranges do not match')
        end if

        allocate(b_time(b_max_win, n_workers), t_time(b_max_win, n_workers))
        allocate(b_tx(b_max_win, n_workers), b_rx(b_max_win, n_workers))
        allocate(t_tx(b_max_win, n_workers), t_rx(b_max_win, n_workers))
        allocate(b_cls(b_max_win, n_workers), t_cls(b_max_win, n_workers))
        allocate(b_seen(b_max_win, n_workers), t_seen(b_max_win, n_workers))

        call load_standard_csv(trim(baseline_input), '__BASELINE_METADATA_JSON_BEGIN__', b_max_win, n_workers, &
            b_time, b_cls, b_tx, b_rx, b_seen)
        call load_standard_csv(trim(threat_signature_input), '__THREAT_SIGNATURE_METADATA_JSON_BEGIN__', b_max_win, n_workers, &
            t_time, t_cls, t_tx, t_rx, t_seen)

        do w = b_min_win, b_max_win
            do s = 1, n_workers
                if (.not. b_seen(w,s)) call abort_with_message('baseline file is missing a required window/sensor row')
                if (.not. t_seen(w,s)) call abort_with_message('threat signature file is missing a required window/sensor row')
                if (abs(b_time(w,s) - t_time(w,s)) > 1.0e-6_dp) then
                    call abort_with_message('baseline/threat time grid mismatch')
                end if
                if (b_cls(w,s) /= t_cls(w,s)) then
                    call abort_with_message('baseline/threat class grid mismatch')
                end if
            end do
        end do

        found_active = .false.
        active_start = huge(1)
        active_end = -huge(1)
        do w = b_min_win, b_max_win
            do s = 1, n_workers
                if (t_tx(w,s) > 0.0_dp .or. t_rx(w,s) > 0.0_dp) then
                    found_active = .true.
                    active_start = min(active_start, w)
                    active_end = max(active_end, w)
                end if
            end do
        end do
        if (.not. found_active) call abort_with_message('no nonzero threat activity detected')

        if (auto_window_from_threat) then
            replay_start = max(b_min_win, active_start - replay_padding_windows)
            replay_end = min(b_max_win, active_end + replay_padding_windows)
            baseline_start_window = replay_start
            n_windows = replay_end - replay_start + 1
            start_minute = int(b_time(replay_start,1) / 60.0_dp)
        else
            replay_start = baseline_start_window
            replay_end = baseline_start_window + n_windows - 1
            if (replay_start < b_min_win .or. replay_end > b_max_win) then
                call abort_with_message('manual replay interval is outside available baseline/threat range')
            end if
        end if

        tx_min = huge(1.0_dp)
        tx_max = -huge(1.0_dp)
        rx_min = huge(1.0_dp)
        rx_max = -huge(1.0_dp)
        do s = 1, n_workers
            do w = replay_start, replay_end
                tx_mbps = bytes_per_window_to_mbps(baseline_tx_scale * (b_tx(w,s) + t_tx(w,s)), window_seconds)
                rx_mbps = bytes_per_window_to_mbps(baseline_rx_scale * (b_rx(w,s) + t_rx(w,s)), window_seconds)
                tx_min(s) = min(tx_min(s), tx_mbps)
                tx_max(s) = max(tx_max(s), tx_mbps)
                rx_min(s) = min(rx_min(s), rx_mbps)
                rx_max(s) = max(rx_max(s), rx_mbps)
            end do
        end do

        write(*,*) ''
        write(*,*) 'Replay preflight validation'
        write(*,*) '==========================='
        write(*,*) 'Config file              : ', trim(path)
        write(*,*) 'Baseline input           : ', trim(baseline_input)
        write(*,*) 'Threat signature input   : ', trim(threat_signature_input)
        write(*,*) ''
        write(*,*) 'Baseline range:'
        write(*,'("  Start time:       ",A,"  (window ",I0,")")') clock_from_seconds(b_min_t), b_min_win
        write(*,'("  Stop time:        ",A,"  (window ",I0,")")') clock_from_seconds(b_max_t), b_max_win
        write(*,'("  Window size:      ",I0," seconds")') window_seconds
        write(*,'("  Rows checked:     ",I0)') b_rows

        call print_threat_metadata_table(trim(threat_signature_input))

        write(*,*) ''
        write(*,*) 'Autogenerated replay interval:'
        write(*,'("  Start time:       ",A,"  (window ",I0,")")') clock_from_seconds(b_time(replay_start,1)), replay_start
        write(*,'("  Stop time:        ",A,"  (window ",I0,")")') clock_from_seconds(b_time(replay_end,1)), replay_end
        write(*,'("  Window size:      ",I0," seconds")') window_seconds
        write(*,'("  Replay windows:   ",I0)') n_windows
        write(*,'("  Duration:         ",I0," seconds = ",F8.2," minutes")') n_windows * window_seconds, &
            real(n_windows * window_seconds, dp) / 60.0_dp
        write(*,'("  Padding:          ",I0," windows = ",I0," seconds on each side")') replay_padding_windows, &
            replay_padding_windows * window_seconds

        write(*,*) ''
        write(*,*) 'Combined replay target summary:'
        write(*,'(A)') 'Sensor   TX min Mbps   TX max Mbps   RX min Mbps   RX max Mbps   Cap Mbps'
        write(*,'(A)') '------   -----------   -----------   -----------   -----------   --------'
        do s = 1, n_workers
            write(*,'(I6,3X,F11.3,3X,F11.3,3X,F11.3,3X,F11.3,3X,F8.1)') &
                s, tx_min(s), tx_max(s), rx_min(s), rx_max(s), sensor_rate_cap_mbps(s)
            if (abort_on_rate_cap_violation) then
                if (tx_max(s) > sensor_rate_cap_mbps(s) .or. rx_max(s) > sensor_rate_cap_mbps(s)) then
                    call abort_with_message('combined replay target exceeds configured sensor link cap')
                end if
            end if
        end do

        if (dry_run) then
            write(*,*) ''
            write(*,*) 'Dry run is enabled; stopping after preflight validation.'
        else if (require_confirmation) then
            write(output_unit,*) ''
            write(output_unit,'(A)') 'Proceed with this autogenerated replay interval? [y/N]'
            call flush(output_unit)
            read(input_unit,'(A)') answer
            if (.not. is_yes_response(answer)) then
                write(output_unit,'(A)') 'Replay cancelled by user before traffic generation.'
                call flush(output_unit)
                dry_run = .true.
                return
            end if
        end if

        if (.not. dry_run) then
            call confirm_output_overwrite_if_needed(trim(output_file))
        end if

        deallocate(b_time, t_time, b_tx, b_rx, t_tx, t_rx, b_cls, t_cls, b_seen, t_seen)
        flush(output_unit)
    end subroutine preflight_controller


    real(dp) function bytes_per_window_to_mbps(bytes, seconds)
        implicit none
        real(dp), intent(in) :: bytes
        integer, intent(in) :: seconds
        if (seconds <= 0) then
            bytes_per_window_to_mbps = 0.0_dp
        else
            bytes_per_window_to_mbps = 8.0_dp * bytes / real(seconds, dp) / 1.0e6_dp
        end if
    end function bytes_per_window_to_mbps


    character(len=8) function clock_from_seconds(seconds_value)
        implicit none
        real(dp), intent(in) :: seconds_value
        integer :: total_seconds, hour_value, minute_value, second_value
        total_seconds = modulo(int(seconds_value + 0.5_dp), 86400)
        hour_value = total_seconds / 3600
        minute_value = modulo(total_seconds, 3600) / 60
        second_value = modulo(total_seconds, 60)
        write(clock_from_seconds,'(I2.2,":",I2.2,":",I2.2)') hour_value, minute_value, second_value
    end function clock_from_seconds


    subroutine confirm_output_overwrite_if_needed(path)
        implicit none
        character(len=*), intent(in) :: path
        logical :: exists
        character(len=16) :: answer

        inquire(file=trim(path), exist=exists)
        if (.not. exists) return
        if (overwrite_output) return

        if (.not. require_confirmation) then
            call abort_with_message('output file already exists and overwrite_output is false: ' // trim(path))
        end if

        write(output_unit,*) ''
        write(output_unit,*) 'Output file already exists: ', trim(path)
        write(output_unit,'(A)') 'Overwrite it? [y/N]'
        call flush(output_unit)
        read(input_unit,'(A)') answer
        if (.not. is_yes_response(answer)) then
            write(output_unit,'(A)') 'Replay cancelled by user before traffic generation.'
            call flush(output_unit)
            dry_run = .true.
            return
        end if
        overwrite_output = .true.
    end subroutine confirm_output_overwrite_if_needed


    character(len=5) function logical_json(value)
        implicit none
        logical, intent(in) :: value
        if (value) then
            logical_json = 'true '
        else
            logical_json = 'false'
        end if
    end function logical_json


    subroutine write_replay_metadata(unit_num)
        implicit none
        integer, intent(in) :: unit_num
        integer :: replay_end_window

        replay_end_window = baseline_start_window + n_windows - 1

        write(unit_num,'(A)') ''
        write(unit_num,'(A)') '__REPLAY_TARGET_METADATA_JSON_BEGIN__'
        write(unit_num,'(A)') '{'
        write(unit_num,'(A)') '  "generated_by": "replay_target_mpi.f90",'
        write(unit_num,'(A)') '  "config_file": "' // trim(config_file) // '",'
        write(unit_num,'(A)') '  "baseline_input": "' // trim(baseline_input) // '",'
        write(unit_num,'(A)') '  "threat_signature_input": "' // trim(threat_signature_input) // '",'
        write(unit_num,'(A)') '  "data_file": "' // trim(output_file) // '",'
        write(unit_num,'(A)') '  "replay_target": "baseline_plus_threat_signature",'
        write(unit_num,'(A,I0,A)') '  "n_workers": ', n_workers, ','
        write(unit_num,'(A,I0,A)') '  "window_seconds": ', window_seconds, ','
        write(unit_num,'(A,I0,A)') '  "replay_start_window": ', baseline_start_window, ','
        write(unit_num,'(A,I0,A)') '  "replay_stop_window": ', replay_end_window, ','
        write(unit_num,'(A,I0,A)') '  "n_replay_windows": ', n_windows, ','
        write(unit_num,'(A,I0,A)') '  "replay_padding_windows": ', replay_padding_windows, ','
        write(unit_num,'(A)') '  "auto_window_from_threat": ' // logical_json(auto_window_from_threat) // ','
        write(unit_num,'(A)') '  "dry_run": ' // logical_json(dry_run) // ','
        write(unit_num,'(A)') '  "time_unit": "seconds",'
        write(unit_num,'(A)') '  "target_tx_unit": "bytes_per_window",'
        write(unit_num,'(A)') '  "target_rx_unit": "bytes_per_window",'
        write(unit_num,'(A)') '  "delta_tx_unit": "bytes_measured_per_window",'
        write(unit_num,'(A)') '  "delta_rx_unit": "bytes_measured_per_window",'
        write(unit_num,'(A)') '  "rate_conversion": "kbit_per_second = 8 * bytes_per_window / window_seconds / 1000",'
        write(unit_num,'(A)') '  "columns": ['
        write(unit_num,'(A)') '    {"name": "window", "unit": "replay_window_index"},'
        write(unit_num,'(A)') '    {"name": "time_seconds", "unit": "seconds_from_replay_start"},'
        write(unit_num,'(A)') '    {"name": "wall_clock_minutes", "unit": "minutes_from_midnight"},'
        write(unit_num,'(A)') '    {"name": "wall_clock_hhmmss", "unit": "hh:mm:ss"},'
        write(unit_num,'(A)') '    {"name": "sensor", "unit": "index"},'
        write(unit_num,'(A)') '    {"name": "class", "unit": "index"},'
        write(unit_num,'(A)') '    {"name": "target_tx", "unit": "bytes_per_window"},'
        write(unit_num,'(A)') '    {"name": "target_rx", "unit": "bytes_per_window"},'
        write(unit_num,'(A)') '    {"name": "target_tx_rate_kbit", "unit": "kbit_per_second"},'
        write(unit_num,'(A)') '    {"name": "target_rx_rate_kbit", "unit": "kbit_per_second"},'
        write(unit_num,'(A)') '    {"name": "delta_tx", "unit": "bytes_measured_per_window"},'
        write(unit_num,'(A)') '    {"name": "delta_rx", "unit": "bytes_measured_per_window"},'
        write(unit_num,'(A)') '    {"name": "activity", "unit": "bytes_measured_per_window"},'
        write(unit_num,'(A)') '    {"name": "direction", "unit": "unitless"}'
        write(unit_num,'(A)') '  ]'
        write(unit_num,'(A)') '}'
        write(unit_num,'(A)') '__REPLAY_TARGET_METADATA_JSON_END__'
    end subroutine write_replay_metadata

    subroutine read_baseline_for_sensor(path, desired_sensor, tx_values, rx_values)
        implicit none
        character(len=*), intent(in) :: path
        integer, intent(in) :: desired_sensor
        real(dp), intent(out) :: tx_values(:)
        real(dp), intent(out) :: rx_values(:)

        integer :: unit_num
        integer :: ios_local
        integer :: win
        integer :: sensor
        integer :: cls
        integer :: local_idx
        real(dp) :: tsec
        real(dp) :: tx
        real(dp) :: rx
        real(dp) :: act
        real(dp) :: dir
        character(len=1024) :: line
        logical :: ok

        tx_values = 0.0_dp
        rx_values = 0.0_dp

        unit_num = 31
        open(unit=unit_num, file=trim(path), status='old', action='read', iostat=ios_local)

        if (ios_local /= 0) then
            write(error_unit,*) 'ERROR: rank ', desired_sensor, ' could not open baseline file: ', trim(path)
            flush(error_unit)
            call MPI_Abort(comm, 1, ierr)
        end if

        read(unit_num,'(A)',iostat=ios_local) line
        if (trim(line) /= 'window,time_seconds,sensor,class,delta_tx,delta_rx,activity,direction') then
            write(error_unit,*) 'ERROR: unexpected baseline CSV header in ', trim(path)
            flush(error_unit)
            call MPI_Abort(comm, 1, ierr)
        end if

        do
            read(unit_num,'(A)',iostat=ios_local) line
            if (ios_local /= 0) exit
            if (len_trim(line) == 0) cycle
            if (index(line, '__BASELINE_METADATA_JSON_BEGIN__') > 0) exit

            call parse_telemetry_line(line, win, tsec, sensor, cls, tx, rx, act, dir, ok)
            if (.not. ok) cycle

            if (sensor == desired_sensor) then
                local_idx = win - baseline_start_window + 1

                if (local_idx >= 1 .and. local_idx <= size(tx_values)) then
                    tx_values(local_idx) = tx
                    rx_values(local_idx) = rx
                end if
            end if
        end do

        close(unit_num)

        write(*,'("rank ",I0," baseline TX first/max = ",ES14.6," ",ES14.6,"; RX first/max = ",ES14.6," ",ES14.6)') &
            desired_sensor, tx_values(1), maxval(tx_values), rx_values(1), maxval(rx_values)
        flush(output_unit)
    end subroutine read_baseline_for_sensor



    subroutine add_threat_signature_for_sensor(path, desired_sensor, tx_values, rx_values)
        implicit none
        character(len=*), intent(in) :: path
        integer, intent(in) :: desired_sensor
        real(dp), intent(inout) :: tx_values(:)
        real(dp), intent(inout) :: rx_values(:)

        integer :: unit_num
        integer :: ios_local
        integer :: win
        integer :: sensor
        integer :: active_count
        integer :: local_idx
        integer :: added_rows
        real(dp) :: tsec
        real(dp) :: threat_tx
        real(dp) :: threat_rx
        real(dp) :: act_value
        real(dp) :: dir_value
        character(len=1024) :: line
        logical :: ok

        added_rows = 0
        unit_num = 32
        open(unit=unit_num, file=trim(path), status='old', action='read', iostat=ios_local)

        if (ios_local /= 0) then
            write(error_unit,*) 'ERROR: rank ', desired_sensor, ' could not open threat signature file: ', trim(path)
            flush(error_unit)
            call MPI_Abort(comm, 1, ierr)
        end if

        read(unit_num,'(A)',iostat=ios_local) line
        if (trim(line) /= 'window,time_seconds,sensor,class,delta_tx,delta_rx,activity,direction') then
            write(error_unit,*) 'ERROR: unexpected threat signature CSV header in ', trim(path)
            flush(error_unit)
            call MPI_Abort(comm, 1, ierr)
        end if

        do
            read(unit_num,'(A)',iostat=ios_local) line
            if (ios_local /= 0) exit
            if (len_trim(line) == 0) cycle

            if (index(line, '__THREAT_SIGNATURE_METADATA_JSON_BEGIN__') > 0) exit

            call parse_telemetry_line(line, win, tsec, sensor, active_count, threat_tx, threat_rx, &
                act_value, dir_value, ok)
            if (.not. ok) cycle

            if (sensor == desired_sensor) then
                local_idx = win - baseline_start_window + 1

                if (local_idx >= 1 .and. local_idx <= size(tx_values)) then
                    tx_values(local_idx) = tx_values(local_idx) + threat_tx
                    rx_values(local_idx) = rx_values(local_idx) + threat_rx
                    if (threat_tx > 0.0_dp .or. threat_rx > 0.0_dp) then
                        added_rows = added_rows + 1
                    end if
                end if
            end if
        end do

        close(unit_num)

        write(*,'("rank ",I0," threat rows added = ",I0)') desired_sensor, added_rows
        write(*,'("rank ",I0," replay target TX first/max = ",ES14.6," ",ES14.6,"; RX first/max = ",ES14.6," ",ES14.6)') &
            desired_sensor, tx_values(1), maxval(tx_values), rx_values(1), maxval(rx_values)
        flush(output_unit)
    end subroutine add_threat_signature_for_sensor


    subroutine read_all_replay_target_rx(baseline_path, threat_path, rx_targets)
        implicit none
        character(len=*), intent(in) :: baseline_path
        character(len=*), intent(in) :: threat_path
        real(dp), intent(out) :: rx_targets(:,:)
        real(dp), allocatable :: tx_dummy(:)
        real(dp), allocatable :: rx_temp(:)
        integer :: k

        allocate(tx_dummy(n_windows))
        allocate(rx_temp(n_windows))

        rx_targets = 0.0_dp

        do k = 1, n_workers
            call read_baseline_for_sensor(baseline_path, k, tx_dummy, rx_temp)
            call add_threat_signature_for_sensor(threat_path, k, tx_dummy, rx_temp)
            rx_targets(:,k) = rx_temp(:)
        end do

        deallocate(tx_dummy)
        deallocate(rx_temp)
    end subroutine read_all_replay_target_rx


    subroutine parse_telemetry_line(line, win, tsec, sensor, cls, tx, rx, act, dir, ok)
        implicit none
        character(len=*), intent(in) :: line
        integer, intent(out) :: win
        real(dp), intent(out) :: tsec
        integer, intent(out) :: sensor
        integer, intent(out) :: cls
        real(dp), intent(out) :: tx
        real(dp), intent(out) :: rx
        real(dp), intent(out) :: act
        real(dp), intent(out) :: dir
        logical, intent(out) :: ok

        character(len=len(line)) :: clean_line
        integer :: ios_local
        integer :: idx

        clean_line = line

        do idx = 1, len_trim(clean_line)
            if (clean_line(idx:idx) == ',') clean_line(idx:idx) = ' '
        end do

        win = 0
        tsec = 0.0_dp
        sensor = 0
        cls = 0
        tx = 0.0_dp
        rx = 0.0_dp
        act = 0.0_dp
        dir = 0.0_dp

        read(clean_line,*,iostat=ios_local) win, tsec, sensor, cls, tx, rx, act, dir

        ok = (ios_local == 0)
    end subroutine parse_telemetry_line


    subroutine read_counter(path, value)
        implicit none
        character(len=*), intent(in) :: path
        integer(i8), intent(out) :: value
        integer :: unit_num
        integer :: ios_local

        value = 0_i8
        unit_num = 30

        open(unit=unit_num, file=trim(path), status='old', action='read', iostat=ios_local)

        if (ios_local /= 0) then
            write(error_unit,*) 'ERROR: could not read network counter: ', trim(path)
            flush(error_unit)
            call cleanup_all_local()
            call MPI_Abort(comm, 1, ierr)
        end if

        read(unit_num,*,iostat=ios_local) value
        close(unit_num)

        if (ios_local /= 0) then
            write(error_unit,*) 'ERROR: invalid counter value in: ', trim(path)
            flush(error_unit)
            call cleanup_all_local()
            call MPI_Abort(comm, 1, ierr)
        end if
    end subroutine read_counter



    function wall_clock_string(start_minute_local, elapsed_seconds) result(clock_text)
        implicit none
        integer, intent(in) :: start_minute_local
        real(dp), intent(in) :: elapsed_seconds
        character(len=8) :: clock_text
        integer :: total_seconds
        integer :: hour_value
        integer :: minute_value
        integer :: second_value

        total_seconds = modulo(start_minute_local * 60 + int(elapsed_seconds + 0.5_dp), 86400)
        hour_value = total_seconds / 3600
        minute_value = modulo(total_seconds, 3600) / 60
        second_value = modulo(total_seconds, 60)

        write(clock_text,'(I2.2,":",I2.2,":",I2.2)') hour_value, minute_value, second_value
    end function wall_clock_string


    integer function reporting_class(minute_absolute)
        implicit none
        integer, intent(in) :: minute_absolute
        integer :: minute_of_day

        minute_of_day = modulo(minute_absolute, 1440)

        if (minute_of_day < 450) then
            reporting_class = 1
        else if (minute_of_day < 540) then
            reporting_class = 2
        else if (minute_of_day < 705) then
            reporting_class = 3
        else if (minute_of_day < 795) then
            reporting_class = 4
        else if (minute_of_day < 1020) then
            reporting_class = 5
        else if (minute_of_day < 1140) then
            reporting_class = 6
        else if (minute_of_day < 1200) then
            reporting_class = 7
        else if (minute_of_day < 1320) then
            reporting_class = 8
        else
            reporting_class = 9
        end if
    end function reporting_class

pure function lower_string(s) result(out)
    character(len=*), intent(in) :: s
    character(len=len(s)) :: out
    integer :: i, ia

    out = s
    do i = 1, len(s)
        ia = iachar(out(i:i))
        if (ia >= iachar('A') .and. ia <= iachar('Z')) then
            out(i:i) = achar(ia + 32)
        end if
    end do
end function lower_string

logical function is_yes_response(s)
    character(len=*), intent(in) :: s
    character(len=:), allocatable :: t

    t = trim(adjustl(lower_string(s)))
    is_yes_response = (t == 'y' .or. t == 'yes')
end function is_yes_response


end program replay_target_mpi
