program baseline_model
    implicit none

    integer, parameter :: dp = kind(1.0d0)
    integer, parameter :: max_sensors = 4
    integer, parameter :: max_classes = 9

    integer :: n_sensors
    integer :: n_classes
    integer :: n_windows
    integer :: window_seconds
    integer :: seed_base

    real(dp) :: drift_coeff
    real(dp) :: jitter_coeff
    real(dp) :: smooth_sigma_windows
    real(dp) :: human_lambda_per_day
    real(dp) :: human_duration_min_seconds
    real(dp) :: human_duration_max_seconds
    real(dp) :: human_mu_log
    real(dp) :: human_sigma_log

    integer :: class_start_minute(max_classes)
    real(dp) :: tx_class_bytes(max_sensors * max_classes)
    real(dp) :: rx_class_bytes(max_sensors * max_classes)

    character(len=256) :: output_file
    character(len=256) :: config_file

    integer :: i
    integer :: s
    integer :: c
    integer :: idx
    integer :: ios
    integer :: seed_size
    integer, allocatable :: seed(:)

    real(dp), allocatable :: time_seconds(:)
    real(dp), allocatable :: baseline_tx(:,:)
    real(dp), allocatable :: baseline_rx(:,:)
    real(dp), allocatable :: drift_tx(:,:)
    real(dp), allocatable :: drift_rx(:,:)
    real(dp), allocatable :: events_tx(:,:)
    real(dp), allocatable :: events_rx(:,:)
    real(dp), allocatable :: structured_tx(:,:)
    real(dp), allocatable :: structured_rx(:,:)
    real(dp), allocatable :: smooth_tx(:,:)
    real(dp), allocatable :: smooth_rx(:,:)
    real(dp), allocatable :: final_tx(:,:)
    real(dp), allocatable :: final_rx(:,:)
    real(dp), allocatable :: pink(:)

    real(dp) :: z
    real(dp) :: tx_bytes
    real(dp) :: rx_bytes
    real(dp) :: activity
    real(dp) :: direction

    namelist /baseline_config/ &
        n_sensors, n_classes, n_windows, window_seconds, seed_base, &
        drift_coeff, jitter_coeff, smooth_sigma_windows, &
        human_lambda_per_day, human_duration_min_seconds, human_duration_max_seconds, &
        human_mu_log, human_sigma_log, &
        class_start_minute, tx_class_bytes, rx_class_bytes, output_file

    ! ============================================================
    ! Defaults. These are overwritten by baseline_model_config.nml.
    ! ============================================================

    n_sensors = 4
    n_classes = 9
    n_windows = 2880
    window_seconds = 30
    seed_base = 13579

    drift_coeff = 0.15_dp
    jitter_coeff = 0.075_dp
    smooth_sigma_windows = 15.0_dp


    human_lambda_per_day = 20.0_dp
    human_duration_min_seconds = 2.0_dp
    human_duration_max_seconds = 10.0_dp
    human_mu_log = log(200000.0_dp)
    human_sigma_log = 0.4_dp

    class_start_minute = (/ 0, 450, 540, 705, 795, 1020, 1140, 1200, 1320 /)

    ! Array order is sensor-fastest by class:
    ! class 1: sensors 1--4, class 2: sensors 1--4, ..., class 9.
    tx_class_bytes = (/ &
        120000.0_dp, 190000.0_dp, 150000.0_dp, 110000.0_dp, &
        520000.0_dp, 650000.0_dp, 580000.0_dp, 360000.0_dp, &
        2050000.0_dp, 1550000.0_dp, 2850000.0_dp, 1250000.0_dp, &
        850000.0_dp, 700000.0_dp, 1100000.0_dp, 520000.0_dp, &
        2450000.0_dp, 1750000.0_dp, 3300000.0_dp, 1450000.0_dp, &
        1550000.0_dp, 1150000.0_dp, 2350000.0_dp, 950000.0_dp, &
        420000.0_dp, 360000.0_dp, 560000.0_dp, 260000.0_dp, &
        1050000.0_dp, 470000.0_dp, 1850000.0_dp, 320000.0_dp, &
        260000.0_dp, 240000.0_dp, 420000.0_dp, 180000.0_dp /)

    rx_class_bytes = (/ &
        180000.0_dp, 280000.0_dp, 135000.0_dp, 150000.0_dp, &
        950000.0_dp, 1850000.0_dp, 900000.0_dp, 620000.0_dp, &
        2500000.0_dp, 4350000.0_dp, 2350000.0_dp, 1550000.0_dp, &
        1050000.0_dp, 1800000.0_dp, 980000.0_dp, 620000.0_dp, &
        2700000.0_dp, 4100000.0_dp, 2400000.0_dp, 1600000.0_dp, &
        1250000.0_dp, 1900000.0_dp, 1200000.0_dp, 760000.0_dp, &
        460000.0_dp, 560000.0_dp, 360000.0_dp, 260000.0_dp, &
        1150000.0_dp, 720000.0_dp, 1250000.0_dp, 310000.0_dp, &
        330000.0_dp, 370000.0_dp, 280000.0_dp, 190000.0_dp /)

    output_file = 'baseline.csv'
    config_file = 'baseline_model_config.nml'

    ! Optional first command-line argument can specify a different config file.
    call get_command_argument(1, config_file)
    if (len_trim(config_file) == 0) config_file = 'baseline_model_config.nml'

    open(unit=20, file=trim(config_file), status='old', action='read', iostat=ios)
    if (ios == 0) then
        read(20, nml=baseline_config)
        close(20)
        print *, 'Read config file: ', trim(config_file)
    else
        print *, 'Config file not found; using internal defaults: ', trim(config_file)
    end if

    if (n_sensors /= max_sensors) then
        print *, 'ERROR: this implementation expects n_sensors = 4.'
        stop 1
    end if

    if (n_classes /= max_classes) then
        print *, 'ERROR: this implementation expects n_classes = 9.'
        stop 1
    end if

    allocate(time_seconds(n_windows))
    allocate(baseline_tx(n_windows, n_sensors))
    allocate(baseline_rx(n_windows, n_sensors))
    allocate(drift_tx(n_windows, n_sensors))
    allocate(drift_rx(n_windows, n_sensors))
    allocate(events_tx(n_windows, n_sensors))
    allocate(events_rx(n_windows, n_sensors))
    allocate(structured_tx(n_windows, n_sensors))
    allocate(structured_rx(n_windows, n_sensors))
    allocate(smooth_tx(n_windows, n_sensors))
    allocate(smooth_rx(n_windows, n_sensors))
    allocate(final_tx(n_windows, n_sensors))
    allocate(final_rx(n_windows, n_sensors))
    allocate(pink(n_windows))

    ! ============================================================
    ! Reproducible random seed
    ! ============================================================

    call random_seed(size=seed_size)
    allocate(seed(seed_size))

    do i = 1, seed_size
        seed(i) = seed_base + 104729 * i
    end do

    call random_seed(put=seed)

    baseline_tx = 0.0_dp
    baseline_rx = 0.0_dp
    drift_tx = 0.0_dp
    drift_rx = 0.0_dp
    events_tx = 0.0_dp
    events_rx = 0.0_dp
    structured_tx = 0.0_dp
    structured_rx = 0.0_dp
    smooth_tx = 0.0_dp
    smooth_rx = 0.0_dp
    final_tx = 0.0_dp
    final_rx = 0.0_dp

    ! ============================================================
    ! Logic-table baseline B(t)
    ! ============================================================

    do i = 1, n_windows
        time_seconds(i) = real(i - 1, dp) * real(window_seconds, dp)
        c = activity_class_from_minute(int(modulo(time_seconds(i) / 60.0_dp, 1440.0_dp)))

        do s = 1, n_sensors
            idx = s + (c - 1) * n_sensors
            baseline_tx(i, s) = tx_class_bytes(idx)
            baseline_rx(i, s) = rx_class_bytes(idx)
        end do
    end do

    ! ============================================================
    ! Drift D(t) = B(t) d P(t), with normalized pink noise P(t)
    ! ============================================================

    do s = 1, n_sensors
        call make_pink_noise(pink, n_windows)
        do i = 1, n_windows
            drift_tx(i, s) = baseline_tx(i, s) * drift_coeff * pink(i)
        end do

        call make_pink_noise(pink, n_windows)
        do i = 1, n_windows
            drift_rx(i, s) = baseline_rx(i, s) * drift_coeff * pink(i)
        end do
    end do

    ! ============================================================
    ! Event term E(t) = A(t)
    ! Human burst events only; no separate heartbeat traffic process.
    ! ============================================================

    do s = 1, n_sensors
        call add_human_bursts(events_tx(:, s), n_windows, real(window_seconds, dp), &
            human_lambda_per_day, human_duration_min_seconds, human_duration_max_seconds, &
            human_mu_log, human_sigma_log)

        call add_human_bursts(events_rx(:, s), n_windows, real(window_seconds, dp), &
            human_lambda_per_day, human_duration_min_seconds, human_duration_max_seconds, &
            human_mu_log, human_sigma_log)
    end do

    ! ============================================================
    ! S_structured(t) = B(t) + D(t) + E(t)
    ! ============================================================

    structured_tx = baseline_tx + drift_tx + events_tx
    structured_rx = baseline_rx + drift_rx + events_rx

    do i = 1, n_windows
        do s = 1, n_sensors
            if (structured_tx(i, s) < 0.0_dp) structured_tx(i, s) = 0.0_dp
            if (structured_rx(i, s) < 0.0_dp) structured_rx(i, s) = 0.0_dp
        end do
    end do

    ! ============================================================
    ! Gaussian smoothing of structured signal
    ! ============================================================

    do s = 1, n_sensors
        call gaussian_smooth_circular(structured_tx(:, s), smooth_tx(:, s), n_windows, smooth_sigma_windows)
        call gaussian_smooth_circular(structured_rx(:, s), smooth_rx(:, s), n_windows, smooth_sigma_windows)
    end do

    ! ============================================================
    ! Add jitter after smoothing:
    ! J(t) = Y_smooth(t) k Z(t)
    ! ============================================================

    do i = 1, n_windows
        do s = 1, n_sensors
            z = randn()
            final_tx(i, s) = smooth_tx(i, s) + smooth_tx(i, s) * jitter_coeff * z

            z = randn()
            final_rx(i, s) = smooth_rx(i, s) + smooth_rx(i, s) * jitter_coeff * z

            if (final_tx(i, s) < 0.0_dp) final_tx(i, s) = 0.0_dp
            if (final_rx(i, s) < 0.0_dp) final_rx(i, s) = 0.0_dp
        end do
    end do

    ! ============================================================
    ! Write baseline.csv in long format expected by replay tooling
    ! ============================================================

    open(unit=10, file=trim(output_file), status='replace', action='write')
    write(10, '(A)') 'window,time_seconds,sensor,class,delta_tx,delta_rx,activity,direction'

    do i = 1, n_windows
        c = activity_class_from_minute(int(modulo(time_seconds(i) / 60.0_dp, 1440.0_dp)))

        do s = 1, n_sensors
            tx_bytes = final_tx(i, s)
            rx_bytes = final_rx(i, s)
            activity = tx_bytes + rx_bytes

            if (activity > 0.0_dp) then
                direction = (tx_bytes - rx_bytes) / activity
            else
                direction = 0.0_dp
            end if

            write(10, '(I0,",",F10.1,",",I0,",",I0,",",F14.3,",",F14.3,",",F14.3,",",F12.6)') &
                i, time_seconds(i), s, c, tx_bytes, rx_bytes, activity, direction
        end do
    end do

    write(10, '(A)') ''
    write(10, '(A)') '__BASELINE_METADATA_JSON_BEGIN__'
    call write_metadata_json_body(10, output_file, config_file)
    write(10, '(A)') '__BASELINE_METADATA_JSON_END__'

    close(10)

    print *, 'Wrote baseline file with embedded metadata: ', trim(output_file)

contains

    subroutine write_metadata_json_body(unit_id, csv_file, cfg_file)
        implicit none
        integer, intent(in) :: unit_id
        character(len=*), intent(in) :: csv_file
        character(len=*), intent(in) :: cfg_file

        write(unit_id, '(A)') '{'
        write(unit_id, '(A)') '  "generated_by": "baseline_model.f90",'
        write(unit_id, '(A)') '  "config_file": "' // trim(json_escape(cfg_file)) // '",'
        write(unit_id, '(A)') '  "data_file": "' // trim(json_escape(csv_file)) // '",'
        write(unit_id, '(A,I0,A)') '  "n_sensors": ', n_sensors, ','
        write(unit_id, '(A,I0,A)') '  "n_classes": ', n_classes, ','
        write(unit_id, '(A,I0,A)') '  "n_windows": ', n_windows, ','
        write(unit_id, '(A,I0,A)') '  "window_seconds": ', window_seconds, ','
        write(unit_id, '(A,I0,A)') '  "seed_base": ', seed_base, ','
        write(unit_id, '(A)') '  "time_unit": "seconds",'
        write(unit_id, '(A)') '  "delta_tx_unit": "bytes_per_window",'
        write(unit_id, '(A)') '  "delta_rx_unit": "bytes_per_window",'
        write(unit_id, '(A)') '  "activity_unit": "bytes_per_window",'
        write(unit_id, '(A)') '  "direction_unit": "unitless",'
        write(unit_id, '(A)') '  "columns": ['
        write(unit_id, '(A)') '    {"name": "window", "unit": "index"},'
        write(unit_id, '(A)') '    {"name": "time_seconds", "unit": "seconds"},'
        write(unit_id, '(A)') '    {"name": "sensor", "unit": "index"},'
        write(unit_id, '(A)') '    {"name": "class", "unit": "index"},'
        write(unit_id, '(A)') '    {"name": "delta_tx", "unit": "bytes_per_window"},'
        write(unit_id, '(A)') '    {"name": "delta_rx", "unit": "bytes_per_window"},'
        write(unit_id, '(A)') '    {"name": "activity", "unit": "bytes_per_window"},'
        write(unit_id, '(A)') '    {"name": "direction", "unit": "unitless"}'
        write(unit_id, '(A)') '  ],'
        call write_class_schedule_json(unit_id)
        call write_class_baselines_json(unit_id)
        write(unit_id, '(A,F10.6,A)') '  "drift_coeff": ', drift_coeff, ','
        write(unit_id, '(A,F10.6,A)') '  "jitter_coeff": ', jitter_coeff, ','
        write(unit_id, '(A,F10.6,A)') '  "smooth_sigma_windows": ', smooth_sigma_windows, ','
        write(unit_id, '(A,F10.6,A)') '  "human_lambda_per_day": ', human_lambda_per_day, ','
        write(unit_id, '(A,F10.6,A)') '  "human_duration_min_seconds": ', human_duration_min_seconds, ','
        write(unit_id, '(A,F10.6,A)') '  "human_duration_max_seconds": ', human_duration_max_seconds, ','
        write(unit_id, '(A,F16.11,A)') '  "human_mu_log": ', human_mu_log, ','
        write(unit_id, '(A,F10.6)') '  "human_sigma_log": ', human_sigma_log
        write(unit_id, '(A)') '}'
    end subroutine write_metadata_json_body


    subroutine write_class_schedule_json(unit_id)
        implicit none
        integer, intent(in) :: unit_id

        integer :: j
        integer :: start_second

        write(unit_id, '(A)') '  "class_schedule": ['

        do j = 1, n_classes
            start_second = class_start_minute(j) * 60

            if (j < n_classes) then
                write(unit_id, '(A,I0,A,I0,A,I0,A)') &
                    '    {"class": ', j, ', "start_minute": ', class_start_minute(j), &
                    ', "start_seconds": ', start_second, '},'
            else
                write(unit_id, '(A,I0,A,I0,A,I0,A)') &
                    '    {"class": ', j, ', "start_minute": ', class_start_minute(j), &
                    ', "start_seconds": ', start_second, '}'
            end if
        end do

        write(unit_id, '(A)') '  ],'
    end subroutine write_class_schedule_json


    subroutine write_class_baselines_json(unit_id)
        implicit none
        integer, intent(in) :: unit_id

        integer :: j
        integer :: ss
        integer :: ii

        write(unit_id, '(A)') '  "class_baseline_bytes_per_window": ['

        do j = 1, n_classes
            if (j < n_classes) then
                write(unit_id, '(A,I0,A)', advance='no') '    {"class": ', j, ', "tx": ['
            else
                write(unit_id, '(A,I0,A)', advance='no') '    {"class": ', j, ', "tx": ['
            end if

            do ss = 1, n_sensors
                ii = ss + (j - 1) * n_sensors
                if (ss < n_sensors) then
                    write(unit_id, '(F18.3,A)', advance='no') tx_class_bytes(ii), ','
                else
                    write(unit_id, '(F18.3,A)', advance='no') tx_class_bytes(ii), '], "rx": ['
                end if
            end do

            do ss = 1, n_sensors
                ii = ss + (j - 1) * n_sensors
                if (ss < n_sensors) then
                    write(unit_id, '(F18.3,A)', advance='no') rx_class_bytes(ii), ','
                else
                    if (j < n_classes) then
                        write(unit_id, '(F18.3,A)') rx_class_bytes(ii), ']},'
                    else
                        write(unit_id, '(F18.3,A)') rx_class_bytes(ii), ']}'
                    end if
                end if
            end do
        end do

        write(unit_id, '(A)') '  ],'
    end subroutine write_class_baselines_json


    function json_escape(text) result(out)
        implicit none
        character(len=*), intent(in) :: text
        character(len=512) :: out

        ! Filenames in this workflow are expected to be simple path strings.
        ! Copy as-is for readable metadata.
        out = text
    end function json_escape

    function activity_class_from_minute(minute_of_day) result(cls)
        implicit none
        integer, intent(in) :: minute_of_day
        integer :: cls
        integer :: j

        cls = 1
        do j = 1, n_classes
            if (minute_of_day >= class_start_minute(j)) cls = j
        end do
    end function activity_class_from_minute


    subroutine make_pink_noise(p, n)
        implicit none
        integer, intent(in) :: n
        real(dp), intent(out) :: p(n)

        real(dp), allocatable :: w(:)
        complex(dp), allocatable :: spec(:)
        complex(dp), allocatable :: filt(:)

        integer :: ii
        integer :: kk
        integer :: freq_index
        real(dp) :: angle
        real(dp) :: pi
        real(dp) :: weight
        real(dp) :: mean_p
        real(dp) :: std_p

        pi = 4.0_dp * atan(1.0_dp)

        allocate(w(n))
        allocate(spec(n))
        allocate(filt(n))

        do ii = 1, n
            w(ii) = randn()
        end do

        ! Forward DFT.
        do kk = 1, n
            spec(kk) = cmplx(0.0_dp, 0.0_dp, kind=dp)

            do ii = 1, n
                angle = -2.0_dp * pi * real((kk - 1) * (ii - 1), dp) / real(n, dp)
                spec(kk) = spec(kk) + cmplx(cos(angle), sin(angle), kind=dp) * w(ii)
            end do
        end do

        ! Pink weighting H_p(f): zero DC, f^{-1/2} otherwise.
        do kk = 1, n
            if (kk == 1) then
                weight = 0.0_dp
            else
                freq_index = min(kk - 1, n - (kk - 1))
                if (freq_index <= 0) then
                    weight = 0.0_dp
                else
                    weight = 1.0_dp / sqrt(real(freq_index, dp))
                end if
            end if

            filt(kk) = spec(kk) * weight
        end do

        ! Inverse DFT.
        do ii = 1, n
            p(ii) = 0.0_dp

            do kk = 1, n
                angle = 2.0_dp * pi * real((kk - 1) * (ii - 1), dp) / real(n, dp)
                p(ii) = p(ii) + real(filt(kk) * cmplx(cos(angle), sin(angle), kind=dp), dp)
            end do

            p(ii) = p(ii) / real(n, dp)
        end do

        ! Normalize.
        mean_p = sum(p) / real(n, dp)
        std_p = sqrt(sum((p - mean_p)**2) / real(n - 1, dp))

        if (std_p > 0.0_dp) then
            p = (p - mean_p) / std_p
        else
            p = 0.0_dp
        end if

        deallocate(w)
        deallocate(spec)
        deallocate(filt)
    end subroutine make_pink_noise


    subroutine add_human_bursts(events, n, dt, lambda, dmin, dmax, mu_log, sigma_log)
        implicit none
        integer, intent(in) :: n
        real(dp), intent(in) :: dt
        real(dp), intent(in) :: lambda
        real(dp), intent(in) :: dmin
        real(dp), intent(in) :: dmax
        real(dp), intent(in) :: mu_log
        real(dp), intent(in) :: sigma_log
        real(dp), intent(inout) :: events(n)

        integer :: k
        integer :: j
        integer :: w1
        integer :: w2
        integer :: win
        real(dp) :: u
        real(dp) :: start_t
        real(dp) :: duration
        real(dp) :: stop_t
        real(dp) :: mag
        real(dp) :: win_start
        real(dp) :: win_stop
        real(dp) :: overlap
        real(dp) :: day_seconds

        day_seconds = real(n, dp) * dt

        k = poisson(lambda)

        do j = 1, k
            call random_number(u)
            start_t = u * day_seconds

            call random_number(u)
            duration = dmin + (dmax - dmin) * u

            stop_t = min(start_t + duration, day_seconds)

            mag = lognormal(mu_log, sigma_log)

            w1 = int(start_t / dt) + 1
            w2 = int(stop_t / dt) + 1

            do win = max(1, w1), min(n, w2)
                win_start = real(win - 1, dp) * dt
                win_stop = real(win, dp) * dt

                overlap = max(0.0_dp, min(stop_t, win_stop) - max(start_t, win_start))

                if (overlap > 0.0_dp) then
                    events(win) = events(win) + mag * (overlap / dt)
                end if
            end do
        end do
    end subroutine add_human_bursts


    subroutine gaussian_smooth_circular(x, y, n, sigma)
        implicit none
        integer, intent(in) :: n
        real(dp), intent(in) :: x(n)
        real(dp), intent(out) :: y(n)
        real(dp), intent(in) :: sigma

        integer :: ii
        integer :: offset
        integer :: jj
        integer :: radius
        real(dp) :: weight
        real(dp) :: accum
        real(dp) :: norm

        radius = max(1, int(4.0_dp * sigma))

        do ii = 1, n
            accum = 0.0_dp
            norm = 0.0_dp

            do offset = -radius, radius
                jj = 1 + modulo(ii - 1 + offset, n)
                weight = exp(-0.5_dp * (real(offset, dp) / sigma)**2)

                accum = accum + weight * x(jj)
                norm = norm + weight
            end do

            if (norm > 0.0_dp) then
                y(ii) = accum / norm
            else
                y(ii) = x(ii)
            end if
        end do
    end subroutine gaussian_smooth_circular


    function poisson(lambda) result(k)
        implicit none
        real(dp), intent(in) :: lambda
        integer :: k
        real(dp) :: l
        real(dp) :: p
        real(dp) :: u

        l = exp(-lambda)
        k = 0
        p = 1.0_dp

        do
            k = k + 1
            call random_number(u)
            p = p * u

            if (p <= l) exit
        end do

        k = k - 1
    end function poisson


    function lognormal(mu_log, sigma_log) result(x)
        implicit none
        real(dp), intent(in) :: mu_log
        real(dp), intent(in) :: sigma_log
        real(dp) :: x

        x = exp(mu_log + sigma_log * randn())
    end function lognormal


    function randn() result(z)
        implicit none
        real(dp) :: z
        real(dp) :: u1
        real(dp) :: u2
        real(dp) :: pi

        pi = 4.0_dp * atan(1.0_dp)

        call random_number(u1)
        call random_number(u2)

        if (u1 < 1.0e-12_dp) u1 = 1.0e-12_dp

        z = sqrt(-2.0_dp * log(u1)) * cos(2.0_dp * pi * u2)
    end function randn

end program baseline_model
