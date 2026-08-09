program threat_detection
    implicit none

    integer, parameter :: dp = kind(1.0d0)
    real(dp), parameter :: threat_epsilon_bytes = 1.0_dp
    integer, parameter :: max_sensors = 16
    integer, parameter :: max_len = 256
    integer, parameter :: line_len = 4096

    integer :: n_sensors
    integer :: n_windows
    integer :: window_seconds
    integer :: baseline_start_window
    integer :: telemetry_row_count_meta
    integer :: replay_stop_window

    real(dp) :: w_time
    real(dp) :: w_magnitude
    real(dp) :: w_persistence
    real(dp) :: w_direction

    real(dp) :: k_time
    real(dp) :: k_tx
    real(dp) :: k_rx
    real(dp) :: k_persistence
    real(dp) :: k_direction

    real(dp) :: persistence_threshold_seconds
    real(dp) :: persistence_trigger_threshold

    real(dp) :: low_likelihood_threshold
    real(dp) :: moderate_likelihood_threshold
    real(dp) :: high_likelihood_threshold

    character(len=max_len) :: telemetry_input_file
    character(len=max_len) :: baseline_input_file
    character(len=max_len) :: output_file
    character(len=max_len) :: global_output_file
    character(len=max_len) :: correlation_output_file
    character(len=max_len) :: correlation_matrix_output_file
    character(len=max_len) :: config_file

    logical :: enable_correlation_analysis
    character(len=max_len) :: correlation_direction
    character(len=max_len) :: correlation_window_source
    integer :: correlation_max_lag_windows

    real(dp) :: alarm_correlation_threshold
    integer :: alarm_min_strong_edges
    integer :: alarm_lag_tolerance_windows
    real(dp) :: alarm_min_consistency_fraction

    integer, allocatable :: baseline_window(:,:)
    integer, allocatable :: class_id(:,:)

    real(dp), allocatable :: time_seconds(:,:)

    real(dp), allocatable :: baseline_tx(:,:)
    real(dp), allocatable :: baseline_rx(:,:)

    real(dp), allocatable :: target_tx(:,:)
    real(dp), allocatable :: target_rx(:,:)

    real(dp), allocatable :: measured_tx(:,:)
    real(dp), allocatable :: measured_rx(:,:)

    real(dp), allocatable :: inferred_threat_tx(:,:)
    real(dp), allocatable :: inferred_threat_rx(:,:)

    real(dp), allocatable :: residual_tx(:,:)
    real(dp), allocatable :: residual_rx(:,:)
    real(dp), allocatable :: correlation_raw(:,:)
    real(dp), allocatable :: correlation_z(:,:)
    real(dp), allocatable :: correlation_matrix(:,:)
    real(dp), allocatable :: correlation_matrix_support(:,:)
    logical, allocatable :: correlation_mask(:,:)

    real(dp), allocatable :: x_time(:,:)
    real(dp), allocatable :: x_magnitude(:,:)
    real(dp), allocatable :: x_persistence(:,:)
    real(dp), allocatable :: x_direction(:,:)

    real(dp), allocatable :: p_local(:,:)
    real(dp), allocatable :: p_avg(:)
    real(dp), allocatable :: p_sys(:)

    integer, allocatable :: consecutive_count(:)

    integer :: i
    integer :: s
    integer :: ios
    integer :: row_count_telemetry
    integer :: row_count_baseline

    real(dp) :: baseline_activity
    real(dp) :: activity
    real(dp) :: z_t
    real(dp) :: z_tx
    real(dp) :: z_rx
    real(dp) :: z_p
    real(dp) :: z_d
    real(dp) :: direction
    real(dp) :: expected_direction
    real(dp) :: q_seconds
    real(dp) :: weight_sum

    namelist /threat_detection_config/ &
        telemetry_input_file, baseline_input_file, output_file, global_output_file, &
        correlation_output_file, correlation_matrix_output_file, &
        enable_correlation_analysis, correlation_direction, correlation_window_source, &
        correlation_max_lag_windows, &
        alarm_correlation_threshold, alarm_min_strong_edges, &
        alarm_lag_tolerance_windows, alarm_min_consistency_fraction, &
        w_time, w_magnitude, w_persistence, w_direction, &
        k_time, k_tx, k_rx, k_persistence, k_direction, &
        persistence_threshold_seconds, persistence_trigger_threshold, &
        low_likelihood_threshold, moderate_likelihood_threshold, high_likelihood_threshold

    ! ============================================================
    ! Defaults. These are overwritten by threat_detection_config.nml.
    ! ============================================================

    telemetry_input_file = 'replay_target_telemetry.csv'
    baseline_input_file = 'baseline.csv'
    output_file = 'threat_detection.csv'
    global_output_file = 'threat_detection_global.csv'
    correlation_output_file = 'threat_detection_correlation.csv'
    correlation_matrix_output_file = 'threat_detection_correlation_matrix.csv'

    enable_correlation_analysis = .true.
    correlation_direction = 'tx'
    correlation_window_source = 'target_threat'
    correlation_max_lag_windows = 19

    alarm_correlation_threshold = 0.70_dp
    alarm_min_strong_edges = 3
    alarm_lag_tolerance_windows = 1
    alarm_min_consistency_fraction = 0.50_dp

    n_sensors = 0
    n_windows = 0
    window_seconds = 0
    baseline_start_window = 0
    replay_stop_window = 0
    telemetry_row_count_meta = 0

    w_time = 0.25_dp
    w_magnitude = 0.35_dp
    w_persistence = 0.25_dp
    w_direction = 0.15_dp

    k_time = 2.0_dp
    k_tx = 2.0_dp
    k_rx = 2.0_dp
    k_persistence = 2.0_dp
    k_direction = 2.0_dp

    persistence_threshold_seconds = 120.0_dp
    persistence_trigger_threshold = 0.05_dp

    low_likelihood_threshold = 0.25_dp
    moderate_likelihood_threshold = 0.50_dp
    high_likelihood_threshold = 0.75_dp

    config_file = 'threat_detection_config.nml'

    call get_command_argument(1, config_file)
    if (len_trim(config_file) == 0) config_file = 'threat_detection_config.nml'

    open(unit=20, file=trim(config_file), status='old', action='read', iostat=ios)
    if (ios == 0) then
        read(20, nml=threat_detection_config)
        close(20)
        print *, 'Read config file: ', trim(config_file)
    else
        print *, 'ERROR: could not open config file: ', trim(config_file)
        stop 1
    end if

    call inspect_telemetry_input(trim(telemetry_input_file))
    call validate_config()

    allocate(baseline_window(n_windows, n_sensors))
    allocate(class_id(n_windows, n_sensors))
    allocate(time_seconds(n_windows, n_sensors))

    allocate(baseline_tx(n_windows, n_sensors))
    allocate(baseline_rx(n_windows, n_sensors))

    allocate(target_tx(n_windows, n_sensors))
    allocate(target_rx(n_windows, n_sensors))

    allocate(measured_tx(n_windows, n_sensors))
    allocate(measured_rx(n_windows, n_sensors))

    allocate(inferred_threat_tx(n_windows, n_sensors))
    allocate(inferred_threat_rx(n_windows, n_sensors))
    allocate(residual_tx(n_windows, n_sensors))
    allocate(residual_rx(n_windows, n_sensors))
    allocate(correlation_raw(n_windows, n_sensors))
    allocate(correlation_z(n_windows, n_sensors))
    allocate(correlation_matrix(n_sensors, n_sensors))
    allocate(correlation_matrix_support(n_sensors, n_sensors))
    allocate(correlation_mask(n_windows, n_sensors))

    allocate(x_time(n_windows, n_sensors))
    allocate(x_magnitude(n_windows, n_sensors))
    allocate(x_persistence(n_windows, n_sensors))
    allocate(x_direction(n_windows, n_sensors))

    allocate(p_local(n_windows, n_sensors))
    allocate(p_avg(n_windows))
    allocate(p_sys(n_windows))

    allocate(consecutive_count(n_sensors))

    baseline_window = 0
    class_id = 0
    time_seconds = 0.0_dp

    baseline_tx = 0.0_dp
    baseline_rx = 0.0_dp
    target_tx = 0.0_dp
    target_rx = 0.0_dp
    measured_tx = 0.0_dp
    measured_rx = 0.0_dp
    inferred_threat_tx = 0.0_dp
    inferred_threat_rx = 0.0_dp
    residual_tx = 0.0_dp
    residual_rx = 0.0_dp
    correlation_raw = 0.0_dp
    correlation_z = 0.0_dp
    correlation_matrix = 0.0_dp
    correlation_matrix_support = 0.0_dp
    correlation_mask = .false.

    x_time = 0.0_dp
    x_magnitude = 0.0_dp
    x_persistence = 0.0_dp
    x_direction = 0.0_dp
    p_local = 0.0_dp
    p_avg = 0.0_dp
    p_sys = 0.0_dp

    call read_replay_target_telemetry(trim(telemetry_input_file), row_count_telemetry)
    call read_baseline_segment(trim(baseline_input_file), row_count_baseline)

    if (row_count_telemetry /= n_windows * n_sensors) then
        print *, 'WARNING: expected telemetry rows = ', n_windows * n_sensors, &
            ' but read rows = ', row_count_telemetry
    end if

    if (row_count_baseline /= n_windows * n_sensors) then
        print *, 'WARNING: expected baseline segment rows = ', n_windows * n_sensors, &
            ' but read rows = ', row_count_baseline
    end if

    inferred_threat_tx = target_tx - baseline_tx
    inferred_threat_rx = target_rx - baseline_rx


    ! Suppress sub-byte floating-point subtraction noise.
    where (abs(inferred_threat_tx) <= threat_epsilon_bytes)
       inferred_threat_tx = 0.0_dp
    end where
    where (abs(inferred_threat_rx) <= threat_epsilon_bytes)
       inferred_threat_rx = 0.0_dp
    end where
    residual_tx = measured_tx - baseline_tx
    residual_rx = measured_rx - baseline_rx

    call validate_input_grids()

    consecutive_count = 0

    do i = 1, n_windows
        p_avg(i) = 0.0_dp
        p_sys(i) = 1.0_dp

        do s = 1, n_sensors
            activity = measured_tx(i,s) + measured_rx(i,s)
            baseline_activity = baseline_tx(i,s) + baseline_rx(i,s)

            if (baseline_activity > 0.0_dp) then
                z_t = (activity - baseline_activity) / baseline_activity
            else
                z_t = 0.0_dp
            end if

            if (baseline_tx(i,s) > 0.0_dp) then
                z_tx = (measured_tx(i,s) - baseline_tx(i,s)) / baseline_tx(i,s)
            else
                z_tx = 0.0_dp
            end if

            if (baseline_rx(i,s) > 0.0_dp) then
                z_rx = (measured_rx(i,s) - baseline_rx(i,s)) / baseline_rx(i,s)
            else
                z_rx = 0.0_dp
            end if

            x_time(i,s) = positive_tanh(k_time * z_t)
            x_magnitude(i,s) = max(positive_tanh(k_tx * z_tx), positive_tanh(k_rx * z_rx))

            if (max(x_time(i,s), x_magnitude(i,s)) > persistence_trigger_threshold) then
                consecutive_count(s) = consecutive_count(s) + 1
            else
                consecutive_count(s) = 0
            end if

            q_seconds = real(consecutive_count(s), dp) * real(window_seconds, dp)
            z_p = (q_seconds - persistence_threshold_seconds) / persistence_threshold_seconds
            x_persistence(i,s) = positive_tanh(k_persistence * z_p)

            if (activity > 0.0_dp) then
                direction = (measured_tx(i,s) - measured_rx(i,s)) / activity

                if (baseline_activity > 0.0_dp) then
                    expected_direction = (baseline_tx(i,s) - baseline_rx(i,s)) / baseline_activity
                else
                    expected_direction = 0.0_dp
                end if

                z_d = abs(direction - expected_direction)
                x_direction(i,s) = tanh(k_direction * z_d)
            else
                direction = 0.0_dp
                expected_direction = 0.0_dp
                z_d = 0.0_dp
                x_direction(i,s) = 0.0_dp
            end if

            p_local(i,s) = w_time * x_time(i,s) + &
                           w_magnitude * x_magnitude(i,s) + &
                           w_persistence * x_persistence(i,s) + &
                           w_direction * x_direction(i,s)

            p_avg(i) = p_avg(i) + p_local(i,s)
            p_sys(i) = p_sys(i) * (1.0_dp - p_local(i,s))
        end do

        p_avg(i) = p_avg(i) / real(n_sensors, dp)
        p_sys(i) = 1.0_dp - p_sys(i)
    end do

    if (enable_correlation_analysis) then
        call prepare_correlation_signals()
        call write_correlation_output(trim(correlation_output_file))
        call write_correlation_matrix_output(trim(correlation_matrix_output_file))
    end if

    call write_detection_output(trim(output_file))
    call write_global_output(trim(global_output_file))
    call write_summary_to_screen()
    call write_results_log(derive_results_filename(trim(output_file)))

    print *, 'Wrote detection file          : ', trim(output_file)
    print *, 'Wrote global detection file   : ', trim(global_output_file)

    if (enable_correlation_analysis) then
        print *, 'Wrote correlation file        : ', trim(correlation_output_file)
        print *, 'Wrote correlation peak matrix file : ', trim(correlation_matrix_output_file)
    end if

    print *, 'Wrote results log             : ', trim(derive_results_filename(trim(output_file)))

contains

    subroutine validate_config()
        implicit none

        weight_sum = w_time + w_magnitude + w_persistence + w_direction

        if (n_sensors <= 0 .or. n_sensors > max_sensors) then
            print *, 'ERROR: n_sensors must be in [1,max_sensors].'
            stop 1
        end if

        if (n_windows <= 0) then
            print *, 'ERROR: n_windows must be positive.'
            stop 1
        end if

        if (window_seconds <= 0) then
            print *, 'ERROR: window_seconds must be positive.'
            stop 1
        end if

        if (baseline_start_window <= 0) then
            print *, 'ERROR: baseline_start_window must be positive.'
            stop 1
        end if

        if (abs(weight_sum - 1.0_dp) > 1.0e-8_dp) then
            print *, 'ERROR: anomaly weights must sum to 1.0.'
            print *, 'Weight sum = ', weight_sum
            stop 1
        end if

        if (persistence_threshold_seconds <= 0.0_dp) then
            print *, 'ERROR: persistence_threshold_seconds must be positive.'
            stop 1
        end if

        if (persistence_trigger_threshold < 0.0_dp) then
            print *, 'ERROR: persistence_trigger_threshold must be nonnegative.'
            stop 1
        end if

        if (low_likelihood_threshold < 0.0_dp .or. low_likelihood_threshold > 1.0_dp) then
            print *, 'ERROR: low_likelihood_threshold must be in [0,1].'
            stop 1
        end if

        if (moderate_likelihood_threshold < 0.0_dp .or. moderate_likelihood_threshold > 1.0_dp) then
            print *, 'ERROR: moderate_likelihood_threshold must be in [0,1].'
            stop 1
        end if

        if (high_likelihood_threshold < 0.0_dp .or. high_likelihood_threshold > 1.0_dp) then
            print *, 'ERROR: high_likelihood_threshold must be in [0,1].'
            stop 1
        end if

        if (.not. (low_likelihood_threshold < moderate_likelihood_threshold .and. &
                   moderate_likelihood_threshold < high_likelihood_threshold)) then
            print *, 'ERROR: likelihood thresholds must satisfy low < moderate < high.'
            stop 1
        end if

        if (correlation_max_lag_windows < 0) then
            print *, 'ERROR: correlation_max_lag_windows must be nonnegative.'
            stop 1
        end if

        if (correlation_max_lag_windows >= n_windows) then
            print *, 'WARNING: correlation_max_lag_windows exceeds derived n_windows-1; capping to ', n_windows - 1
            correlation_max_lag_windows = n_windows - 1
        end if

        if (alarm_correlation_threshold < -1.0_dp .or. alarm_correlation_threshold > 1.0_dp) then
            print *, 'ERROR: alarm_correlation_threshold must be in [-1,1].'
            stop 1
        end if

        if (alarm_min_strong_edges < 1) then
            print *, 'ERROR: alarm_min_strong_edges must be positive.'
            stop 1
        end if

        if (alarm_lag_tolerance_windows < 0) then
            print *, 'ERROR: alarm_lag_tolerance_windows must be nonnegative.'
            stop 1
        end if

        if (alarm_min_consistency_fraction < 0.0_dp .or. alarm_min_consistency_fraction > 1.0_dp) then
            print *, 'ERROR: alarm_min_consistency_fraction must be in [0,1].'
            stop 1
        end if

        correlation_direction = lower_string(trim(correlation_direction))
        if (trim(correlation_direction) /= 'tx' .and. &
            trim(correlation_direction) /= 'rx' .and. &
            trim(correlation_direction) /= 'activity') then
            print *, 'ERROR: correlation_direction must be tx, rx, or activity.'
            stop 1
        end if

        correlation_window_source = lower_string(trim(correlation_window_source))
        if (trim(correlation_window_source) /= 'target_threat' .and. &
            trim(correlation_window_source) /= 'local_detection' .and. &
            trim(correlation_window_source) /= 'full_experiment') then
            print *, 'ERROR: correlation_window_source must be target_threat, local_detection, or full_experiment.'
            stop 1
        end if
    end subroutine validate_config




    subroutine inspect_telemetry_input(path)
        implicit none
        character(len=*), intent(in) :: path

        character(len=line_len) :: line
        character(len=line_len), allocatable :: fields(:)
        integer :: n_fields
        integer :: ios_local
        integer :: win
        integer :: sensor
        integer :: max_win
        integer :: max_sensor
        integer :: row_count
        logical :: in_metadata
        logical :: found_metadata
        logical :: found_replay_start
        logical :: found_window_seconds
        integer :: metadata_replay_start
        integer :: metadata_replay_stop
        integer :: metadata_n_windows
        integer :: metadata_window_seconds

        max_win = 0
        max_sensor = 0
        row_count = 0
        in_metadata = .false.
        found_metadata = .false.
        found_replay_start = .false.
        found_window_seconds = .false.
        metadata_replay_start = 0
        metadata_replay_stop = 0
        metadata_n_windows = 0
        metadata_window_seconds = 0
        allocate(fields(20))

        open(unit=25, file=trim(path), status='old', action='read', iostat=ios_local)
        if (ios_local /= 0) then
            print *, 'ERROR: could not open telemetry input file for inspection: ', trim(path)
            stop 1
        end if

        read(25, '(A)', iostat=ios_local) line
        if (ios_local /= 0) then
            print *, 'ERROR: empty telemetry input file.'
            stop 1
        end if

        if (index(trim(line), 'window,time_seconds,wall_clock_minutes,wall_clock_hhmmss,sensor,class,target_tx,target_rx') /= 1) then
            print *, 'ERROR: unexpected replay telemetry header during inspection.'
            print *, trim(line)
            stop 1
        end if

        do
            read(25, '(A)', iostat=ios_local) line
            if (ios_local /= 0) exit

            if (trim(line) == '__REPLAY_TARGET_METADATA_JSON_BEGIN__') then
                in_metadata = .true.
                found_metadata = .true.
                cycle
            end if

            if (trim(line) == '__REPLAY_TARGET_METADATA_JSON_END__') exit

            if (in_metadata) then
                if (index(line, '"replay_start_window"') > 0) then
                    metadata_replay_start = extract_json_int(line)
                    found_replay_start = .true.
                else if (index(line, '"replay_stop_window"') > 0) then
                    metadata_replay_stop = extract_json_int(line)
                else if (index(line, '"n_replay_windows"') > 0) then
                    metadata_n_windows = extract_json_int(line)
                else if (index(line, '"window_seconds"') > 0) then
                    metadata_window_seconds = extract_json_int(line)
                    found_window_seconds = .true.
                end if
            else
                if (len_trim(line) == 0) cycle
                call split_csv_line(line, fields, n_fields)
                if (n_fields < 14) then
                    print *, 'ERROR: malformed telemetry data row during inspection.'
                    print *, trim(line)
                    stop 1
                end if

                read(fields(1), *, iostat=ios_local) win
                if (ios_local /= 0) then
                    print *, 'ERROR: could not parse telemetry window during inspection.'
                    print *, trim(line)
                    stop 1
                end if

                read(fields(5), *, iostat=ios_local) sensor
                if (ios_local /= 0) then
                    print *, 'ERROR: could not parse telemetry sensor during inspection.'
                    print *, trim(line)
                    stop 1
                end if

                max_win = max(max_win, win)
                max_sensor = max(max_sensor, sensor)
                row_count = row_count + 1
            end if
        end do

        close(25)

        if (.not. found_metadata) then
            print *, 'ERROR: replay telemetry metadata block not found.'
            stop 1
        end if

        if (.not. found_replay_start) then
            print *, 'ERROR: replay_start_window not found in replay telemetry metadata.'
            stop 1
        end if

        if (.not. found_window_seconds) then
            print *, 'ERROR: window_seconds not found in replay telemetry metadata.'
            stop 1
        end if

        if (max_win <= 0 .or. max_sensor <= 0) then
            print *, 'ERROR: no telemetry data rows found.'
            stop 1
        end if

        if (max_sensor > max_sensors) then
            print *, 'ERROR: telemetry sensor count exceeds max_sensors.'
            stop 1
        end if

        n_windows = max_win
        n_sensors = max_sensor
        baseline_start_window = metadata_replay_start
        replay_stop_window = metadata_replay_stop
        window_seconds = metadata_window_seconds
        telemetry_row_count_meta = row_count

        if (metadata_n_windows > 0 .and. metadata_n_windows /= n_windows) then
            print *, 'ERROR: n_replay_windows metadata does not match telemetry data rows.'
            print *, 'metadata n_replay_windows = ', metadata_n_windows
            print *, 'data max replay window    = ', n_windows
            stop 1
        end if

        if (row_count /= n_windows * n_sensors) then
            print *, 'ERROR: telemetry data grid is incomplete.'
            print *, 'rows found     = ', row_count
            print *, 'expected rows  = ', n_windows * n_sensors
            stop 1
        end if

        print *, 'Telemetry metadata-derived dimensions:'
        print *, '  n_sensors             = ', n_sensors
        print *, '  n_windows             = ', n_windows
        print *, '  window_seconds        = ', window_seconds
        print *, '  baseline_start_window = ', baseline_start_window
    end subroutine inspect_telemetry_input


    integer function extract_json_int(line) result(value)
        implicit none
        character(len=*), intent(in) :: line
        character(len=line_len) :: token
        integer :: pos
        integer :: ios_local

        value = 0
        pos = index(line, ':')
        if (pos <= 0) return

        token = adjustl(line(pos+1:))
        if (index(token, ',') > 0) token = token(:index(token, ',')-1)
        read(token, *, iostat=ios_local) value
        if (ios_local /= 0) value = 0
    end function extract_json_int


    subroutine read_replay_target_telemetry(path, count_rows)
        implicit none
        character(len=*), intent(in) :: path
        integer, intent(out) :: count_rows

        character(len=line_len) :: line
        integer :: win
        integer :: sensor
        integer :: class_value
        integer :: ios_local
        real(dp) :: tsec
        real(dp) :: target_tx_value
        real(dp) :: target_rx_value
        real(dp) :: target_tx_rate_kbit
        real(dp) :: target_rx_rate_kbit
        real(dp) :: measured_tx_value
        real(dp) :: measured_rx_value
        real(dp) :: activity_value
        real(dp) :: direction_value

        count_rows = 0

        open(unit=30, file=trim(path), status='old', action='read', iostat=ios_local)
        if (ios_local /= 0) then
            print *, 'ERROR: could not open telemetry input file: ', trim(path)
            stop 1
        end if

        read(30, '(A)', iostat=ios_local) line
        if (index(trim(line), 'window,time_seconds,wall_clock_minutes,wall_clock_hhmmss,sensor,class,target_tx,target_rx') /= 1) then
            print *, 'ERROR: unexpected replay telemetry header.'
            print *, trim(line)
            stop 1
        end if

        do
            read(30, '(A)', iostat=ios_local) line
            if (ios_local /= 0) exit
            if (trim(line) == '__REPLAY_TARGET_METADATA_JSON_BEGIN__') exit
            if (len_trim(line) == 0) cycle

            call parse_telemetry_line(line, win, tsec, sensor, class_value, &
                target_tx_value, target_rx_value, target_tx_rate_kbit, target_rx_rate_kbit, &
                measured_tx_value, measured_rx_value, activity_value, direction_value)

            if (win < 1 .or. win > n_windows .or. sensor < 1 .or. sensor > n_sensors) then
                print *, 'ERROR: invalid window or sensor in telemetry input file.'
                print *, trim(line)
                stop 1
            end if

            time_seconds(win, sensor) = tsec
            class_id(win, sensor) = class_value
            target_tx(win, sensor) = target_tx_value
            target_rx(win, sensor) = target_rx_value
            measured_tx(win, sensor) = measured_tx_value
            measured_rx(win, sensor) = measured_rx_value

            count_rows = count_rows + 1
        end do

        close(30)
    end subroutine read_replay_target_telemetry



    subroutine parse_telemetry_line(line, win, tsec, sensor, class_value, &
        target_tx_value, target_rx_value, target_tx_rate_kbit, target_rx_rate_kbit, &
        measured_tx_value, measured_rx_value, activity_value, direction_value)

        implicit none
        character(len=*), intent(in) :: line
        integer, intent(out) :: win
        real(dp), intent(out) :: tsec
        integer, intent(out) :: sensor
        integer, intent(out) :: class_value
        real(dp), intent(out) :: target_tx_value
        real(dp), intent(out) :: target_rx_value
        real(dp), intent(out) :: target_tx_rate_kbit
        real(dp), intent(out) :: target_rx_rate_kbit
        real(dp), intent(out) :: measured_tx_value
        real(dp), intent(out) :: measured_rx_value
        real(dp), intent(out) :: activity_value
        real(dp), intent(out) :: direction_value

        character(len=line_len), allocatable :: fields(:)
        integer :: n_fields
        integer :: ios_local

        allocate(fields(20))
        call split_csv_line(line, fields, n_fields)

        if (n_fields < 14) then
            print *, 'ERROR: expected 14 CSV fields in replay-target telemetry line.'
            print *, trim(line)
            stop 1
        end if

        read(fields(1), *, iostat=ios_local) win
        if (ios_local /= 0) stop 'ERROR: could not parse telemetry window.'

        read(fields(2), *, iostat=ios_local) tsec
        if (ios_local /= 0) stop 'ERROR: could not parse telemetry time_seconds.'

        read(fields(5), *, iostat=ios_local) sensor
        if (ios_local /= 0) stop 'ERROR: could not parse telemetry sensor.'

        read(fields(6), *, iostat=ios_local) class_value
        if (ios_local /= 0) stop 'ERROR: could not parse telemetry class.'

        read(fields(7), *, iostat=ios_local) target_tx_value
        if (ios_local /= 0) stop 'ERROR: could not parse target_tx.'

        read(fields(8), *, iostat=ios_local) target_rx_value
        if (ios_local /= 0) stop 'ERROR: could not parse target_rx.'

        read(fields(9), *, iostat=ios_local) target_tx_rate_kbit
        if (ios_local /= 0) stop 'ERROR: could not parse target_tx_rate_kbit.'

        read(fields(10), *, iostat=ios_local) target_rx_rate_kbit
        if (ios_local /= 0) stop 'ERROR: could not parse target_rx_rate_kbit.'

        read(fields(11), *, iostat=ios_local) measured_tx_value
        if (ios_local /= 0) stop 'ERROR: could not parse measured delta_tx.'

        read(fields(12), *, iostat=ios_local) measured_rx_value
        if (ios_local /= 0) stop 'ERROR: could not parse measured delta_rx.'

        read(fields(13), *, iostat=ios_local) activity_value
        if (ios_local /= 0) stop 'ERROR: could not parse activity.'

        read(fields(14), *, iostat=ios_local) direction_value
        if (ios_local /= 0) stop 'ERROR: could not parse direction.'
    end subroutine parse_telemetry_line


    subroutine read_baseline_segment(path, count_rows)
        implicit none
        character(len=*), intent(in) :: path
        integer, intent(out) :: count_rows

        character(len=line_len) :: line
        integer :: baseline_win
        integer :: replay_win
        integer :: sensor
        integer :: class_value
        integer :: ios_local
        real(dp) :: tsec
        real(dp) :: baseline_tx_value
        real(dp) :: baseline_rx_value
        real(dp) :: activity_value
        real(dp) :: direction_value

        count_rows = 0

        open(unit=40, file=trim(path), status='old', action='read', iostat=ios_local)
        if (ios_local /= 0) then
            print *, 'ERROR: could not open baseline input file: ', trim(path)
            stop 1
        end if

        read(40, '(A)', iostat=ios_local) line
        if (index(trim(line), 'window,time_seconds,sensor,class,delta_tx,delta_rx,activity,direction') /= 1) then
            print *, 'ERROR: unexpected baseline header.'
            print *, trim(line)
            stop 1
        end if

        do
            read(40, '(A)', iostat=ios_local) line
            if (ios_local /= 0) exit
            if (trim(line) == '__BASELINE_METADATA_JSON_BEGIN__') exit
            if (len_trim(line) == 0) cycle

            call parse_baseline_line(line, baseline_win, tsec, sensor, class_value, &
                baseline_tx_value, baseline_rx_value, activity_value, direction_value)

            if (baseline_win >= baseline_start_window .and. &
                baseline_win <= baseline_start_window + n_windows - 1) then

                if (sensor < 1 .or. sensor > n_sensors) then
                    print *, 'ERROR: invalid sensor in baseline input file.'
                    print *, trim(line)
                    stop 1
                end if

                replay_win = baseline_win - baseline_start_window + 1

                baseline_window(replay_win, sensor) = baseline_win
                baseline_tx(replay_win, sensor) = baseline_tx_value
                baseline_rx(replay_win, sensor) = baseline_rx_value

                count_rows = count_rows + 1
            end if
        end do

        close(40)
    end subroutine read_baseline_segment


    subroutine parse_baseline_line(line, win, tsec, sensor, class_value, tx_value, rx_value, activity_value, direction_value)
        implicit none
        character(len=*), intent(in) :: line
        integer, intent(out) :: win
        real(dp), intent(out) :: tsec
        integer, intent(out) :: sensor
        integer, intent(out) :: class_value
        real(dp), intent(out) :: tx_value
        real(dp), intent(out) :: rx_value
        real(dp), intent(out) :: activity_value
        real(dp), intent(out) :: direction_value

        character(len=line_len), allocatable :: fields(:)
        integer :: n_fields
        integer :: ios_local

        allocate(fields(20))
        call split_csv_line(line, fields, n_fields)

        if (n_fields < 8) then
            print *, 'ERROR: expected at least 8 CSV fields in baseline line.'
            print *, trim(line)
            stop 1
        end if

        read(fields(1), *, iostat=ios_local) win
        if (ios_local /= 0) stop 'ERROR: could not parse baseline window.'

        read(fields(2), *, iostat=ios_local) tsec
        if (ios_local /= 0) stop 'ERROR: could not parse baseline time_seconds.'

        read(fields(3), *, iostat=ios_local) sensor
        if (ios_local /= 0) stop 'ERROR: could not parse baseline sensor.'

        read(fields(4), *, iostat=ios_local) class_value
        if (ios_local /= 0) stop 'ERROR: could not parse baseline class.'

        read(fields(5), *, iostat=ios_local) tx_value
        if (ios_local /= 0) stop 'ERROR: could not parse baseline delta_tx.'

        read(fields(6), *, iostat=ios_local) rx_value
        if (ios_local /= 0) stop 'ERROR: could not parse baseline delta_rx.'

        read(fields(7), *, iostat=ios_local) activity_value
        if (ios_local /= 0) stop 'ERROR: could not parse baseline activity.'

        read(fields(8), *, iostat=ios_local) direction_value
        if (ios_local /= 0) stop 'ERROR: could not parse baseline direction.'
    end subroutine parse_baseline_line


    subroutine validate_input_grids()
        implicit none
        integer :: win
        integer :: sensor

        do win = 1, n_windows
            do sensor = 1, n_sensors
                if (baseline_window(win, sensor) /= baseline_start_window + win - 1) then
                    print *, 'ERROR: missing baseline entry for replay window/sensor.'
                    print *, 'replay window = ', win, ' sensor = ', sensor
                    stop 1
                end if

                if (time_seconds(win, sensor) < 0.0_dp) then
                    print *, 'ERROR: invalid telemetry time_seconds.'
                    print *, 'replay window = ', win, ' sensor = ', sensor
                    stop 1
                end if

                if (abs((target_tx(win, sensor) - baseline_tx(win, sensor)) - inferred_threat_tx(win, sensor)) > threat_epsilon_bytes) then
                    print *, 'ERROR: internal target/baseline/threat consistency check failed.'
                    stop 1
                end if
            end do
        end do
    end subroutine validate_input_grids


    subroutine split_csv_line(line, fields, n_fields)
        implicit none
        character(len=*), intent(in) :: line
        character(len=*), intent(out) :: fields(:)
        integer, intent(out) :: n_fields

        integer :: pos
        integer :: start_pos
        integer :: line_length

        n_fields = 0
        start_pos = 1
        line_length = len_trim(line)

        do
            pos = index(line(start_pos:line_length), ',')

            if (pos == 0) then
                n_fields = n_fields + 1
                fields(n_fields) = adjustl(line(start_pos:line_length))
                exit
            else
                n_fields = n_fields + 1
                fields(n_fields) = adjustl(line(start_pos:start_pos + pos - 2))
                start_pos = start_pos + pos
            end if

            if (n_fields >= size(fields)) exit
            if (start_pos > line_length) exit
        end do
    end subroutine split_csv_line



    subroutine prepare_correlation_signals()
        implicit none

        integer :: win
        integer :: sensor
        real(dp) :: mu
        real(dp) :: sigma
        real(dp) :: variance
        real(dp) :: value

        ! ============================================================
        ! Step 1: build the raw residual signal for the selected channel.
        ! ============================================================

        do sensor = 1, n_sensors
            do win = 1, n_windows
                select case (trim(correlation_direction))
                case ('tx')
                    correlation_raw(win, sensor) = residual_tx(win, sensor)
                case ('rx')
                    correlation_raw(win, sensor) = residual_rx(win, sensor)
                case ('activity')
                    correlation_raw(win, sensor) = residual_tx(win, sensor) + residual_rx(win, sensor)
                end select

                select case (trim(correlation_window_source))
                case ('target_threat')
                    correlation_mask(win, sensor) = &
                        (abs(inferred_threat_tx(win, sensor)) > threat_epsilon_bytes .or. &
                         abs(inferred_threat_rx(win, sensor)) > threat_epsilon_bytes)
                case ('local_detection')
                    correlation_mask(win, sensor) = (p_local(win, sensor) >= low_likelihood_threshold)
                case ('full_experiment')
                    correlation_mask(win, sensor) = .true.
                end select
            end do
        end do

        ! ============================================================
        ! Step 2: normalize using the full experimental residual
        ! distribution for each sensor, then apply the local mask.
        !
        ! This is important for square-pulse attacks. If normalization is
        ! performed only on the local support and the pulse is nearly flat,
        ! the local-support variance can collapse to zero and erase the
        ! correlation signal. Full-window normalization preserves the fact
        ! that the pulse is anomalous relative to the whole day/experiment.
        ! ============================================================

        correlation_z = 0.0_dp

        do sensor = 1, n_sensors
            mu = 0.0_dp

            do win = 1, n_windows
                mu = mu + correlation_raw(win, sensor)
            end do

            mu = mu / real(n_windows, dp)

            variance = 0.0_dp

            do win = 1, n_windows
                value = correlation_raw(win, sensor) - mu
                variance = variance + value * value
            end do

            variance = variance / real(n_windows, dp)

            if (variance <= 1.0e-24_dp) then
                correlation_z(:, sensor) = 0.0_dp
                cycle
            end if

            sigma = sqrt(variance)

            do win = 1, n_windows
                if (correlation_mask(win, sensor)) then
                    correlation_z(win, sensor) = (correlation_raw(win, sensor) - mu) / sigma
                else
                    correlation_z(win, sensor) = 0.0_dp
                end if
            end do
        end do

        correlation_matrix = 0.0_dp
        correlation_matrix_support = 0.0_dp
    end subroutine prepare_correlation_signals
    function correlation_at_lag(sensor_i, sensor_j, lag_k) result(corr)
        implicit none
        integer, intent(in) :: sensor_i
        integer, intent(in) :: sensor_j
        integer, intent(in) :: lag_k
        real(dp) :: corr
        integer :: win
        integer :: jwin
        real(dp) :: sum_value

        sum_value = 0.0_dp

        do win = 1, n_windows
            jwin = win + lag_k

            if (jwin >= 1 .and. jwin <= n_windows) then
                sum_value = sum_value + correlation_z(win, sensor_i) * correlation_z(jwin, sensor_j)
            end if
        end do

        corr = sum_value / real(n_windows, dp)
    end function correlation_at_lag


    function correlation_support_at_lag(sensor_i, sensor_j, lag_k) result(corr)
        implicit none
        integer, intent(in) :: sensor_i
        integer, intent(in) :: sensor_j
        integer, intent(in) :: lag_k
        real(dp) :: corr
        integer :: win
        integer :: jwin
        real(dp) :: numerator
        real(dp) :: norm_i
        real(dp) :: norm_j
        real(dp) :: denom

        numerator = 0.0_dp
        norm_i = 0.0_dp
        norm_j = 0.0_dp

        do win = 1, n_windows
            jwin = win + lag_k

            if (jwin >= 1 .and. jwin <= n_windows) then
                numerator = numerator + correlation_z(win, sensor_i) * correlation_z(jwin, sensor_j)
                norm_i = norm_i + correlation_z(win, sensor_i) * correlation_z(win, sensor_i)
                norm_j = norm_j + correlation_z(jwin, sensor_j) * correlation_z(jwin, sensor_j)
            end if
        end do

        denom = sqrt(norm_i * norm_j)

        if (denom > 1.0e-24_dp) then
            corr = numerator / denom
        else
            corr = 0.0_dp
        end if
    end function correlation_support_at_lag


    subroutine write_correlation_output(path)
        implicit none
        character(len=*), intent(in) :: path
        integer :: unit_corr
        integer :: lag_k
        integer :: sensor_i
        integer :: sensor_j
        real(dp) :: corr_value
        real(dp) :: support_value

        open(newunit=unit_corr, file=trim(path), status='replace', action='write', iostat=ios)
        if (ios /= 0) then
            print *, 'ERROR: could not open correlation output file: ', trim(path)
            stop 1
        end if

        write(unit_corr, '(A)') 'internal_k_windows,plot_lag_windows,sensor_i,sensor_j,correlation_fixed_N,correlation_support_normalized'

        do lag_k = -correlation_max_lag_windows, correlation_max_lag_windows
            do sensor_i = 1, n_sensors
                do sensor_j = 1, n_sensors
                    corr_value = correlation_at_lag(sensor_i, sensor_j, lag_k)
                    support_value = correlation_support_at_lag(sensor_i, sensor_j, lag_k)

                    write(unit_corr, '(I0,",",I0,",",I0,",",I0,",",F14.8,",",F14.8)') &
                        lag_k, -lag_k, sensor_i, sensor_j, corr_value, support_value
                end do
            end do
        end do

        call append_threat_detection_metadata(unit_corr, trim(path), 'correlation_lag_scan')
        close(unit_corr)
    end subroutine write_correlation_output


    subroutine write_correlation_matrix_output(path)
        implicit none
        character(len=*), intent(in) :: path
        integer :: unit_matrix
        integer :: sensor_i
        integer :: sensor_j
        integer :: lag_k
        integer :: peak_lag_support
        integer :: peak_lag_fixed_n
        real(dp) :: support_value
        real(dp) :: fixed_n_value
        real(dp) :: peak_support
        real(dp) :: peak_fixed_n
        real(dp) :: fixed_n_at_support_peak
        real(dp) :: support_at_fixed_n_peak

        open(newunit=unit_matrix, file=trim(path), status='replace', action='write', iostat=ios)
        if (ios /= 0) then
            print *, 'ERROR: could not open correlation matrix output file: ', trim(path)
            stop 1
        end if

        write(unit_matrix, '(A)') 'sensor_i,sensor_j,peak_internal_k_support,peak_plot_lag_support,peak_support_normalized,correlation_fixed_N_at_support_peak,peak_internal_k_fixed_N,peak_plot_lag_fixed_N,peak_fixed_N,correlation_support_normalized_at_fixed_N_peak'

        do sensor_i = 1, n_sensors
            do sensor_j = 1, n_sensors
                peak_support = -1.0e99_dp
                peak_fixed_n = -1.0e99_dp
                peak_lag_support = 0
                peak_lag_fixed_n = 0
                fixed_n_at_support_peak = 0.0_dp
                support_at_fixed_n_peak = 0.0_dp

                do lag_k = -correlation_max_lag_windows, correlation_max_lag_windows
                    support_value = correlation_support_at_lag(sensor_i, sensor_j, lag_k)
                    fixed_n_value = correlation_at_lag(sensor_i, sensor_j, lag_k)

                    if (support_value > peak_support) then
                        peak_support = support_value
                        peak_lag_support = lag_k
                        fixed_n_at_support_peak = fixed_n_value
                    end if

                    if (fixed_n_value > peak_fixed_n) then
                        peak_fixed_n = fixed_n_value
                        peak_lag_fixed_n = lag_k
                        support_at_fixed_n_peak = support_value
                    end if
                end do

                write(unit_matrix, '(I0,",",I0,",",I0,",",I0,",",F14.8,",",F14.8,",",I0,",",I0,",",F14.8,",",F14.8)') &
                    sensor_i, sensor_j, peak_lag_support, -peak_lag_support, peak_support, &
                    fixed_n_at_support_peak, peak_lag_fixed_n, -peak_lag_fixed_n, peak_fixed_n, &
                    support_at_fixed_n_peak
            end do
        end do

        call append_threat_detection_metadata(unit_matrix, trim(path), 'correlation_peak_matrix')
        close(unit_matrix)
    end subroutine write_correlation_matrix_output



    subroutine write_detection_output(path)
        implicit none
        character(len=*), intent(in) :: path
        integer :: unit_out
        real(dp) :: display_time

        open(newunit=unit_out, file=trim(path), status='replace', action='write', iostat=ios)
        if (ios /= 0) then
            print *, 'ERROR: could not open output file: ', trim(path)
            stop 1
        end if

        write(unit_out, '(A)') 'window,time_seconds,baseline_window,sensor,class,baseline_tx,baseline_rx,target_tx,target_rx,measured_tx,measured_rx,inferred_threat_tx,inferred_threat_rx,residual_tx,residual_rx,correlation_raw,correlation_mask,correlation_z,x_time,x_magnitude,x_persistence,x_direction,p_local,p_avg,p_sys'

        do i = 1, n_windows
            display_time = real(i - 1, dp) * real(window_seconds, dp)

            do s = 1, n_sensors
                write(unit_out, '(I0,",",F10.1,",",I0,",",I0,",",I0,",",F18.3,",",F18.3,",",F18.3,",",F18.3,",",F18.3,",",F18.3,",",F18.3,",",F18.3,",",F18.3,",",F18.3,",",F18.3,",",L1,",",F12.6,",",F12.6,",",F12.6,",",F12.6,",",F12.6,",",F12.6,",",F12.6,",",F12.6)') &
                    i, display_time, baseline_window(i,s), s, class_id(i,s), &
                    baseline_tx(i,s), baseline_rx(i,s), target_tx(i,s), target_rx(i,s), &
                    measured_tx(i,s), measured_rx(i,s), inferred_threat_tx(i,s), inferred_threat_rx(i,s), &
                    residual_tx(i,s), residual_rx(i,s), correlation_raw(i,s), correlation_mask(i,s), correlation_z(i,s), &
                    x_time(i,s), x_magnitude(i,s), x_persistence(i,s), x_direction(i,s), &
                    p_local(i,s), p_avg(i), p_sys(i)
            end do
        end do

        call append_threat_detection_metadata(unit_out, trim(path), 'detection_detail')
        close(unit_out)
    end subroutine write_detection_output


    subroutine write_global_output(path)
        implicit none
        character(len=*), intent(in) :: path
        integer :: unit_global
        real(dp) :: display_time

        open(newunit=unit_global, file=trim(path), status='replace', action='write', iostat=ios)
        if (ios /= 0) then
            print *, 'ERROR: could not open global output file: ', trim(path)
            stop 1
        end if

        write(unit_global, '(A)') 'window,time_seconds,baseline_window,p_avg,p_sys'

        do i = 1, n_windows
            display_time = real(i - 1, dp) * real(window_seconds, dp)
            write(unit_global, '(I0,",",F10.1,",",I0,",",F12.6,",",F12.6)') &
                i, display_time, baseline_window(i,1), p_avg(i), p_sys(i)
        end do

        call append_threat_detection_metadata(unit_global, trim(path), 'global_detection')
        close(unit_global)
    end subroutine write_global_output



    subroutine write_summary_to_screen()
        implicit none
        call write_summary(6)
    end subroutine write_summary_to_screen


    subroutine write_results_log(path)
        implicit none
        character(len=*), intent(in) :: path
        integer :: unit_log

        open(newunit=unit_log, file=trim(path), status='replace', action='write', iostat=ios)
        if (ios /= 0) then
            print *, 'ERROR: could not open results log file: ', trim(path)
            stop 1
        end if

        write(unit_log,*) 'Read config file: ', trim(config_file)
        write(unit_log,*) 'Telemetry metadata-derived dimensions:'
        write(unit_log,*) '  n_sensors             = ', n_sensors
        write(unit_log,*) '  n_windows             = ', n_windows
        write(unit_log,*) '  window_seconds        = ', window_seconds
        write(unit_log,*) '  baseline_start_window = ', baseline_start_window

        call write_summary(unit_log)

        write(unit_log,*) 'Wrote detection file          : ', trim(output_file)
        write(unit_log,*) 'Wrote global detection file   : ', trim(global_output_file)

        if (enable_correlation_analysis) then
            write(unit_log,*) 'Wrote correlation file        : ', trim(correlation_output_file)
            write(unit_log,*) 'Wrote correlation peak matrix file : ', trim(correlation_matrix_output_file)
        end if

        write(unit_log,*) 'Wrote results log             : ', trim(path)
        close(unit_log)
    end subroutine write_results_log


    function derive_results_filename(csv_path) result(results_path)
        implicit none
        character(len=*), intent(in) :: csv_path
        character(len=max_len) :: results_path
        integer :: dot_pos
        integer :: idx

        results_path = trim(csv_path)
        dot_pos = 0

        do idx = len_trim(results_path), 1, -1
            if (results_path(idx:idx) == '.') then
                dot_pos = idx
                exit
            end if
        end do

        if (dot_pos > 1) then
            results_path = results_path(:dot_pos-1) // '_results.txt'
        else
            results_path = trim(results_path) // '_results.txt'
        end if
    end function derive_results_filename


    subroutine write_summary(unit_summary)
        implicit none
        integer, intent(in) :: unit_summary

        integer :: s_local
        integer :: i_local
        integer :: first_target
        integer :: last_target
        integer :: first_detected
        integer :: last_detected
        integer :: max_local_window
        integer :: max_sys_window
        integer :: max_avg_window
        integer :: first_sys_detected
        integer :: last_sys_detected
        real(dp) :: max_local
        real(dp) :: max_sys
        real(dp) :: max_avg
        real(dp) :: max_xt
        real(dp) :: max_xm
        real(dp) :: max_xp
        real(dp) :: max_xd
        real(dp) :: total_target_threat_tx_mib
        real(dp) :: total_target_threat_rx_mib
        real(dp) :: detected_duration_seconds
        real(dp) :: sys_detected_duration_seconds
        character(len=24) :: conclusion
        character(len=24) :: sys_conclusion

        write(unit_summary,*) ''
        write(unit_summary,*) '============================================================'
        write(unit_summary,*) 'Threat detection summary'
        write(unit_summary,*) '============================================================'
        write(unit_summary,*) 'Telemetry input  : ', trim(telemetry_input_file)
        write(unit_summary,*) 'Baseline input   : ', trim(baseline_input_file)
        write(unit_summary,*) 'Output file      : ', trim(output_file)
        write(unit_summary,*) 'Global output    : ', trim(global_output_file)
        write(unit_summary,*) 'Sensors          : ', n_sensors
        write(unit_summary,*) 'Windows          : ', n_windows
        write(unit_summary,*) 'Window seconds   : ', window_seconds
        write(unit_summary,*) 'Baseline start   : window ', baseline_start_window, &
            ', clock ', trim(clock_string_from_baseline_window(baseline_start_window))
        write(unit_summary,*) 'Observed traffic : measured replay telemetry'
        write(unit_summary,*) 'Expected traffic : baseline segment'
        write(unit_summary,*) ''
        write(unit_summary,*) 'Likelihood tiers :'
        write(unit_summary,'(A,F6.3,A)')       '  No indication  : [0.000, ', low_likelihood_threshold, ')'
        write(unit_summary,'(A,F6.3,A,F6.3,A)') '  Low            : [', low_likelihood_threshold, ', ', moderate_likelihood_threshold, ')'
        write(unit_summary,'(A,F6.3,A,F6.3,A)') '  Moderate       : [', moderate_likelihood_threshold, ', ', high_likelihood_threshold, ')'
        write(unit_summary,'(A,F6.3,A)')       '  High           : [', high_likelihood_threshold, ', 1.000]'
        write(unit_summary,*) ''

        max_sys = -1.0_dp
        max_sys_window = 1
        max_avg = -1.0_dp
        max_avg_window = 1
        first_sys_detected = 0
        last_sys_detected = 0

        do i_local = 1, n_windows
            if (p_sys(i_local) > max_sys) then
                max_sys = p_sys(i_local)
                max_sys_window = i_local
            end if

            if (p_avg(i_local) > max_avg) then
                max_avg = p_avg(i_local)
                max_avg_window = i_local
            end if

            if (p_sys(i_local) >= low_likelihood_threshold) then
                if (first_sys_detected == 0) first_sys_detected = i_local
                last_sys_detected = i_local
            end if
        end do

        sys_conclusion = likelihood_tier(max_sys)

        write(unit_summary,*) 'System-wide conclusion:'
        write(unit_summary,'(A,A)') '  Peak tier               : ', trim(sys_conclusion)
        write(unit_summary,'(A,I0,A,A,A,F10.6)') '  Peak P_sys(t)           : replay window ', max_sys_window, &
            ', clock ', trim(clock_string_from_replay_window(max_sys_window)), ', value ', max_sys
        write(unit_summary,'(A,I0,A,A,A,F10.6)') '  Peak P_avg(t)           : replay window ', max_avg_window, &
            ', clock ', trim(clock_string_from_replay_window(max_avg_window)), ', value ', max_avg

        if (first_sys_detected > 0) then
            sys_detected_duration_seconds = &
                real(last_sys_detected - first_sys_detected + 1, dp) * real(window_seconds, dp)

            write(unit_summary,'(A,I0,A,I0)') '  Detection replay windows: ', first_sys_detected, '--', last_sys_detected
            write(unit_summary,'(A,A,A,A)') '  Detection clock range   : ', &
                trim(clock_string_from_replay_window(first_sys_detected)), '--', &
                trim(clock_string_from_replay_window_end(last_sys_detected))
            write(unit_summary,'(A,F8.1,A,F8.2,A)') '  Detection duration      : ', sys_detected_duration_seconds, &
                ' s / ', sys_detected_duration_seconds / 60.0_dp, ' min'
        else
            write(unit_summary,*) '  Detection replay windows: none'
            write(unit_summary,*) '  Detection clock range   : none'
            write(unit_summary,*) '  Detection duration      : 0 s / 0.00 min'
        end if

        write(unit_summary,*) ''
        write(unit_summary,*) 'Per-sensor conclusions:'

        do s_local = 1, n_sensors
            first_target = 0
            last_target = 0
            first_detected = 0
            last_detected = 0
            max_local = -1.0_dp
            max_local_window = 1
            max_xt = 0.0_dp
            max_xm = 0.0_dp
            max_xp = 0.0_dp
            max_xd = 0.0_dp
            total_target_threat_tx_mib = 0.0_dp
            total_target_threat_rx_mib = 0.0_dp

            do i_local = 1, n_windows
                if (abs(inferred_threat_tx(i_local, s_local)) > threat_epsilon_bytes .or. &
                    abs(inferred_threat_rx(i_local, s_local)) > threat_epsilon_bytes) then
                    if (first_target == 0) first_target = i_local
                    last_target = i_local
                end if

                if (p_local(i_local, s_local) >= low_likelihood_threshold) then
                    if (first_detected == 0) first_detected = i_local
                    last_detected = i_local
                end if

                if (p_local(i_local, s_local) > max_local) then
                    max_local = p_local(i_local, s_local)
                    max_local_window = i_local
                end if

                if (x_time(i_local, s_local) > max_xt) max_xt = x_time(i_local, s_local)
                if (x_magnitude(i_local, s_local) > max_xm) max_xm = x_magnitude(i_local, s_local)
                if (x_persistence(i_local, s_local) > max_xp) max_xp = x_persistence(i_local, s_local)
                if (x_direction(i_local, s_local) > max_xd) max_xd = x_direction(i_local, s_local)

                total_target_threat_tx_mib = total_target_threat_tx_mib + &
                    inferred_threat_tx(i_local, s_local) / (1024.0_dp * 1024.0_dp)
                total_target_threat_rx_mib = total_target_threat_rx_mib + &
                    inferred_threat_rx(i_local, s_local) / (1024.0_dp * 1024.0_dp)
            end do

            conclusion = likelihood_tier(max_local)

            write(unit_summary,*) ''
            write(unit_summary,'(A,I0,A,A)') '  Sensor ', s_local, ': ', trim(conclusion)
            write(unit_summary,'(A,I0,A,A,A,F10.6)') '    Peak P_i(t)          : replay window ', max_local_window, &
                ', clock ', trim(clock_string_from_replay_window(max_local_window)), ', value ', max_local

            if (first_detected > 0) then
                detected_duration_seconds = &
                    real(last_detected - first_detected + 1, dp) * real(window_seconds, dp)

                write(unit_summary,'(A,I0,A,I0)') '    Detection windows    : ', first_detected, '--', last_detected
                write(unit_summary,'(A,A,A,A)') '    Detection clock range : ', &
                    trim(clock_string_from_replay_window(first_detected)), '--', &
                    trim(clock_string_from_replay_window_end(last_detected))
                write(unit_summary,'(A,F8.1,A,F8.2,A)') '    Detection duration    : ', detected_duration_seconds, &
                    ' s / ', detected_duration_seconds / 60.0_dp, ' min'
            else
                write(unit_summary,*) '    Detection windows    : none'
                write(unit_summary,*) '    Detection clock range : none'
                write(unit_summary,*) '    Detection duration    : 0 s / 0.00 min'
            end if

            if (first_target > 0) then
                write(unit_summary,'(A,I0,A,I0)') '    Target threat windows : ', first_target, '--', last_target
                write(unit_summary,'(A,A,A,A)') '    Target threat clock   : ', &
                    trim(clock_string_from_replay_window(first_target)), '--', &
                    trim(clock_string_from_replay_window_end(last_target))
            else
                write(unit_summary,*) '    Target threat windows : none'
                write(unit_summary,*) '    Target threat clock   : none'
            end if

            write(unit_summary,'(A,F8.3,A,F8.3,A,F8.3,A,F8.3)') '    Max components        : time=', max_xt, &
                ', magnitude=', max_xm, ', persistence=', max_xp, ', direction=', max_xd
            write(unit_summary,'(A,F8.1,A,F8.1)') '    Target threat volume  : TX MiB=', &
                total_target_threat_tx_mib, ', RX MiB=', total_target_threat_rx_mib
        end do

        if (enable_correlation_analysis) then
            call write_correlation_summary(unit_summary)
        end if

        write(unit_summary,*) ''
        write(unit_summary,*) '============================================================'
        write(unit_summary,*) ''
    end subroutine write_summary


    subroutine write_correlation_summary(unit_summary)
        implicit none
        integer, intent(in) :: unit_summary
        integer :: sensor_i
        integer :: sensor_j
        integer :: sensor_k
        integer :: lag_k
        integer :: peak_lag_support
        integer :: peak_lag_fixed_n
        integer :: strong_edges
        integer :: checked_triplets
        integer :: consistent_triplets
        integer :: diff_lag
        real(dp) :: support_value
        real(dp) :: fixed_n_value
        real(dp) :: peak_support
        real(dp) :: peak_fixed_n
        real(dp) :: fixed_n_at_support_peak
        real(dp) :: support_at_fixed_n_peak
        real(dp) :: consistency_fraction
        logical :: many_body_alarm

        real(dp), allocatable :: peak_support_matrix(:,:)
        real(dp), allocatable :: peak_fixed_n_matrix(:,:)
        integer, allocatable :: peak_lag_support_matrix(:,:)
        integer, allocatable :: peak_lag_fixed_n_matrix(:,:)
        logical, allocatable :: strong_pair(:,:)

        allocate(peak_support_matrix(n_sensors, n_sensors))
        allocate(peak_fixed_n_matrix(n_sensors, n_sensors))
        allocate(peak_lag_support_matrix(n_sensors, n_sensors))
        allocate(peak_lag_fixed_n_matrix(n_sensors, n_sensors))
        allocate(strong_pair(n_sensors, n_sensors))

        peak_support_matrix = 0.0_dp
        peak_fixed_n_matrix = 0.0_dp
        peak_lag_support_matrix = 0
        peak_lag_fixed_n_matrix = 0
        strong_pair = .false.

        do sensor_i = 1, n_sensors
            do sensor_j = 1, n_sensors
                peak_support = -1.0e99_dp
                peak_fixed_n = -1.0e99_dp
                peak_lag_support = 0
                peak_lag_fixed_n = 0
                fixed_n_at_support_peak = 0.0_dp
                support_at_fixed_n_peak = 0.0_dp

                do lag_k = -correlation_max_lag_windows, correlation_max_lag_windows
                    support_value = correlation_support_at_lag(sensor_i, sensor_j, lag_k)
                    fixed_n_value = correlation_at_lag(sensor_i, sensor_j, lag_k)

                    if (support_value > peak_support) then
                        peak_support = support_value
                        peak_lag_support = lag_k
                        fixed_n_at_support_peak = fixed_n_value
                    end if

                    if (fixed_n_value > peak_fixed_n) then
                        peak_fixed_n = fixed_n_value
                        peak_lag_fixed_n = lag_k
                        support_at_fixed_n_peak = support_value
                    end if
                end do

                peak_support_matrix(sensor_i, sensor_j) = peak_support
                peak_fixed_n_matrix(sensor_i, sensor_j) = peak_fixed_n
                peak_lag_support_matrix(sensor_i, sensor_j) = peak_lag_support
                peak_lag_fixed_n_matrix(sensor_i, sensor_j) = peak_lag_fixed_n
            end do
        end do

        ! ============================================================
        ! Many-body alarm rule.
        !
        ! 1. Keep unordered sensor pairs whose peak support-normalized
        !    correlation exceeds alarm_correlation_threshold.
        ! 2. Test whether their peak-lag matrix is mutually consistent:
        !
        !       k_ij + k_jk ~= k_ik
        !
        !    within alarm_lag_tolerance_windows.
        !
        ! This detects a phase-locked timing graph without requiring a
        ! hard-coded expected lag or sequence.
        ! ============================================================

        strong_edges = 0
        checked_triplets = 0
        consistent_triplets = 0

        do sensor_i = 1, n_sensors
            do sensor_j = sensor_i + 1, n_sensors
                if (peak_support_matrix(sensor_i, sensor_j) >= alarm_correlation_threshold) then
                    strong_pair(sensor_i, sensor_j) = .true.
                    strong_pair(sensor_j, sensor_i) = .true.
                    strong_edges = strong_edges + 1
                end if
            end do
        end do

        do sensor_i = 1, n_sensors
            do sensor_j = sensor_i + 1, n_sensors
                do sensor_k = sensor_j + 1, n_sensors
                    if (strong_pair(sensor_i, sensor_j) .and. &
                        strong_pair(sensor_j, sensor_k) .and. &
                        strong_pair(sensor_i, sensor_k)) then

                        checked_triplets = checked_triplets + 1

                        diff_lag = abs(peak_lag_support_matrix(sensor_i, sensor_j) + &
                                       peak_lag_support_matrix(sensor_j, sensor_k) - &
                                       peak_lag_support_matrix(sensor_i, sensor_k))

                        if (diff_lag <= alarm_lag_tolerance_windows) then
                            consistent_triplets = consistent_triplets + 1
                        end if
                    end if
                end do
            end do
        end do

        if (checked_triplets > 0) then
            consistency_fraction = real(consistent_triplets, dp) / real(checked_triplets, dp)
        else
            consistency_fraction = 0.0_dp
        end if

        many_body_alarm = (strong_edges >= alarm_min_strong_edges .and. &
                           checked_triplets > 0 .and. &
                           consistency_fraction >= alarm_min_consistency_fraction)

        write(unit_summary,*) ''
        write(unit_summary,*) 'Residual correlation summary:'
        write(unit_summary,*) '  Direction        : ', trim(correlation_direction)
        write(unit_summary,*) '  Window source    : ', trim(correlation_window_source)
        write(unit_summary,*) '  Max lag windows  : ', correlation_max_lag_windows
        write(unit_summary,*) '  Lag mode         : blind scan over all allowed lags'
        write(unit_summary,*) '  Normalization    : z-score on full residual window; mask/zero-pad after normalization'
        write(unit_summary,*) '                     fixed-N and support-normalized correlations both reported'
        write(unit_summary,*) ''

        write(unit_summary,*) 'Peak support-normalized correlation matrix:'
        write(unit_summary,*) 'Rows = sensor_i, columns = sensor_j'
        do sensor_i = 1, n_sensors
            write(unit_summary,'(100(F9.4,1X))') (peak_support_matrix(sensor_i, sensor_j), sensor_j = 1, n_sensors)
        end do

        write(unit_summary,*) ''
        write(unit_summary,*) 'Peak internal lag matrix for support-normalized correlation:'
        write(unit_summary,*) 'Rows = sensor_i, columns = sensor_j'
        do sensor_i = 1, n_sensors
            write(unit_summary,'(100(I9,1X))') (peak_lag_support_matrix(sensor_i, sensor_j), sensor_j = 1, n_sensors)
        end do

        write(unit_summary,*) ''
        write(unit_summary,*) 'Peak fixed-N correlation matrix:'
        write(unit_summary,*) 'Rows = sensor_i, columns = sensor_j'
        do sensor_i = 1, n_sensors
            write(unit_summary,'(100(F9.4,1X))') (peak_fixed_n_matrix(sensor_i, sensor_j), sensor_j = 1, n_sensors)
        end do

        write(unit_summary,*) ''
        write(unit_summary,*) 'Pair peak summary:'
        write(unit_summary,*) 'sensor_i sensor_j peak_k_support peak_plot_lag support_corr fixed_N_at_support_peak peak_k_fixed_N peak_plot_lag_fixed_N fixed_N_corr support_at_fixed_N_peak'

        do sensor_i = 1, n_sensors
            do sensor_j = 1, n_sensors
                write(unit_summary,'(I8,1X,I8,1X,I14,1X,I13,1X,F12.6,1X,F23.6,1X,I14,1X,I20,1X,F12.6,1X,F23.6)') &
                    sensor_i, sensor_j, peak_lag_support_matrix(sensor_i, sensor_j), &
                    -peak_lag_support_matrix(sensor_i, sensor_j), &
                    peak_support_matrix(sensor_i, sensor_j), &
                    correlation_at_lag(sensor_i, sensor_j, peak_lag_support_matrix(sensor_i, sensor_j)), &
                    peak_lag_fixed_n_matrix(sensor_i, sensor_j), &
                    -peak_lag_fixed_n_matrix(sensor_i, sensor_j), &
                    peak_fixed_n_matrix(sensor_i, sensor_j), &
                    correlation_support_at_lag(sensor_i, sensor_j, peak_lag_fixed_n_matrix(sensor_i, sensor_j))
            end do
        end do

        write(unit_summary,*) ''
        write(unit_summary,*) 'Many-body coordination alarm:'

        if (many_body_alarm) then
            write(unit_summary,*) '  Alarm Status                 : Alarm'
        else
            write(unit_summary,*) '  Alarm Status                 : No-Alarm'
        end if

        write(unit_summary,'(A,F8.3)') '  Correlation threshold        : ', alarm_correlation_threshold
        write(unit_summary,'(A,I8)')   '  Minimum strong edges         : ', alarm_min_strong_edges
        write(unit_summary,'(A,I8)')   '  Lag tolerance windows        : ', alarm_lag_tolerance_windows
        write(unit_summary,'(A,F8.3)') '  Minimum consistency fraction : ', alarm_min_consistency_fraction
        write(unit_summary,'(A,I8)')   '  Strong unordered edges       : ', strong_edges
        write(unit_summary,'(A,I8)')   '  Checked timing triplets      : ', checked_triplets
        write(unit_summary,'(A,I8)')   '  Consistent timing triplets   : ', consistent_triplets
        write(unit_summary,'(A,F8.3)') '  Consistency fraction         : ', consistency_fraction

        if (many_body_alarm) then
            write(unit_summary,*) '  Interpretation               : coordinated residual timing graph detected'
        else
            write(unit_summary,*) '  Interpretation               : no many-body coordination alarm'
        end if

        write(unit_summary,*) ''
        write(unit_summary,*) 'NOTE: For lagged correlations, C_ij(k)=C_ji(-k).'
        write(unit_summary,*) '      Therefore nonzero-lag matrices are directional, not symmetric.'

        deallocate(peak_support_matrix)
        deallocate(peak_fixed_n_matrix)
        deallocate(peak_lag_support_matrix)
        deallocate(peak_lag_fixed_n_matrix)
        deallocate(strong_pair)
    end subroutine write_correlation_summary




    subroutine append_threat_detection_metadata(unit_out, data_file, output_kind)
        implicit none
        integer, intent(in) :: unit_out
        character(len=*), intent(in) :: data_file
        character(len=*), intent(in) :: output_kind

        write(unit_out, '(A)') ''
        write(unit_out, '(A)') '__THREAT_DETECTION_METADATA_JSON_BEGIN__'
        write(unit_out, '(A)') '{'
        write(unit_out, '(A)') '  "generated_by": "threat_detection.f90",'
        write(unit_out, '(A)') '  "config_file": "' // trim(config_file) // '",'
        write(unit_out, '(A)') '  "telemetry_input_file": "' // trim(telemetry_input_file) // '",'
        write(unit_out, '(A)') '  "baseline_input_file": "' // trim(baseline_input_file) // '",'
        write(unit_out, '(A)') '  "data_file": "' // trim(data_file) // '",'
        write(unit_out, '(A)') '  "output_kind": "' // trim(output_kind) // '",'
        write(unit_out, '(A,I0,A)') '  "n_sensors": ', n_sensors, ','
        write(unit_out, '(A,I0,A)') '  "n_windows": ', n_windows, ','
        write(unit_out, '(A,I0,A)') '  "window_seconds": ', window_seconds, ','
        write(unit_out, '(A,I0,A)') '  "baseline_start_window": ', baseline_start_window, ','
        write(unit_out, '(A,I0,A)') '  "baseline_stop_window": ', baseline_start_window + n_windows - 1, ','
        write(unit_out, '(A)') '  "time_unit": "seconds",'
        write(unit_out, '(A)') '  "input_units": {'
        write(unit_out, '(A)') '    "target_tx": "bytes_per_window",'
        write(unit_out, '(A)') '    "target_rx": "bytes_per_window",'
        write(unit_out, '(A)') '    "measured_tx": "bytes_measured_per_window",'
        write(unit_out, '(A)') '    "measured_rx": "bytes_measured_per_window",'
        write(unit_out, '(A)') '    "baseline_tx": "bytes_per_window",'
        write(unit_out, '(A)') '    "baseline_rx": "bytes_per_window"'
        write(unit_out, '(A)') '  },'
        write(unit_out, '(A)') '  "detection_parameters": {'
        write(unit_out, '(A,F10.6,A)') '    "w_time": ', w_time, ','
        write(unit_out, '(A,F10.6,A)') '    "w_magnitude": ', w_magnitude, ','
        write(unit_out, '(A,F10.6,A)') '    "w_persistence": ', w_persistence, ','
        write(unit_out, '(A,F10.6,A)') '    "w_direction": ', w_direction, ','
        write(unit_out, '(A,F10.6,A)') '    "k_time": ', k_time, ','
        write(unit_out, '(A,F10.6,A)') '    "k_tx": ', k_tx, ','
        write(unit_out, '(A,F10.6,A)') '    "k_rx": ', k_rx, ','
        write(unit_out, '(A,F10.6,A)') '    "k_persistence": ', k_persistence, ','
        write(unit_out, '(A,F10.6,A)') '    "k_direction": ', k_direction, ','
        write(unit_out, '(A,F10.6,A)') '    "persistence_threshold_seconds": ', persistence_threshold_seconds, ','
        write(unit_out, '(A,F10.6,A)') '    "persistence_trigger_threshold": ', persistence_trigger_threshold, ','
        write(unit_out, '(A,F10.6,A)') '    "low_likelihood_threshold": ', low_likelihood_threshold, ','
        write(unit_out, '(A,F10.6,A)') '    "moderate_likelihood_threshold": ', moderate_likelihood_threshold, ','
        write(unit_out, '(A,F10.6)') '    "high_likelihood_threshold": ', high_likelihood_threshold
        write(unit_out, '(A)') '  },'
        write(unit_out, '(A)') '  "correlation_parameters": {'
        if (enable_correlation_analysis) then
            write(unit_out, '(A)') '    "enable_correlation_analysis": true,'
        else
            write(unit_out, '(A)') '    "enable_correlation_analysis": false,'
        end if
        write(unit_out, '(A)') '    "correlation_direction": "' // trim(correlation_direction) // '",'
        write(unit_out, '(A)') '    "correlation_window_source": "' // trim(correlation_window_source) // '",'
        write(unit_out, '(A,I0,A)') '    "correlation_max_lag_windows": ', correlation_max_lag_windows, ','
        write(unit_out, '(A,F10.6,A)') '    "alarm_correlation_threshold": ', alarm_correlation_threshold, ','
        write(unit_out, '(A,I0,A)') '    "alarm_min_strong_edges": ', alarm_min_strong_edges, ','
        write(unit_out, '(A,I0,A)') '    "alarm_lag_tolerance_windows": ', alarm_lag_tolerance_windows, ','
        write(unit_out, '(A,F10.6)') '    "alarm_min_consistency_fraction": ', alarm_min_consistency_fraction
        write(unit_out, '(A)') '  }'
        write(unit_out, '(A)') '}'
        write(unit_out, '(A)') '__THREAT_DETECTION_METADATA_JSON_END__'
    end subroutine append_threat_detection_metadata


    function likelihood_tier(p_value) result(tier)
        implicit none
        real(dp), intent(in) :: p_value
        character(len=24) :: tier

        if (p_value >= high_likelihood_threshold) then
            tier = 'HIGH likelihood'
        else if (p_value >= moderate_likelihood_threshold) then
            tier = 'MODERATE likelihood'
        else if (p_value >= low_likelihood_threshold) then
            tier = 'LOW likelihood'
        else
            tier = 'NO indication'
        end if
    end function likelihood_tier


    function clock_string_from_replay_window(replay_window) result(stamp)
        implicit none
        integer, intent(in) :: replay_window
        character(len=16) :: stamp
        integer :: b_window

        b_window = baseline_start_window + replay_window - 1
        stamp = clock_string_from_baseline_window(b_window)
    end function clock_string_from_replay_window


    function clock_string_from_replay_window_end(replay_window) result(stamp)
        implicit none
        integer, intent(in) :: replay_window
        character(len=16) :: stamp
        real(dp) :: seconds_after_start

        seconds_after_start = real(baseline_start_window + replay_window - 1, dp) * &
            real(window_seconds, dp)
        stamp = clock_string_from_seconds(seconds_after_start)
    end function clock_string_from_replay_window_end


    function clock_string_from_baseline_window(b_window) result(stamp)
        implicit none
        integer, intent(in) :: b_window
        character(len=16) :: stamp
        real(dp) :: seconds_after_start

        seconds_after_start = real(b_window - 1, dp) * real(window_seconds, dp)
        stamp = clock_string_from_seconds(seconds_after_start)
    end function clock_string_from_baseline_window


    function clock_string_from_seconds(seconds_after_start) result(stamp)
        implicit none
        real(dp), intent(in) :: seconds_after_start
        character(len=16) :: stamp
        integer :: total_seconds
        integer :: hh
        integer :: mm
        integer :: ss

        total_seconds = modulo(int(seconds_after_start + 0.5_dp), 24 * 3600)

        hh = total_seconds / 3600
        mm = modulo(total_seconds, 3600) / 60
        ss = modulo(total_seconds, 60)

        write(stamp, '(I2.2,":",I2.2,":",I2.2)') hh, mm, ss
    end function clock_string_from_seconds



    function lower_string(input) result(output)
        implicit none
        character(len=*), intent(in) :: input
        character(len=len(input)) :: output
        integer :: idx
        integer :: ia

        output = input

        do idx = 1, len(input)
            ia = iachar(output(idx:idx))
            if (ia >= iachar('A') .and. ia <= iachar('Z')) then
                output(idx:idx) = achar(ia + 32)
            end if
        end do
    end function lower_string


    function positive_tanh(x) result(y)
        implicit none
        real(dp), intent(in) :: x
        real(dp) :: y

        y = tanh(x)
        if (y < 0.0_dp) y = 0.0_dp
    end function positive_tanh

end program threat_detection
