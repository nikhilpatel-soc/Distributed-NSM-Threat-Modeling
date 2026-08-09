program threat_signature
    implicit none

    integer, parameter :: dp = kind(1.0d0)
    integer, parameter :: max_sensors = 16
    integer, parameter :: max_threat_signatures = 256
    integer, parameter :: max_len = 256
    integer, parameter :: line_len = 4096

    integer :: n_sensors
    integer :: n_windows
    integer :: window_seconds
    integer :: n_threat_signatures
    integer :: seed_base

    integer :: threat_number(max_threat_signatures)
    integer :: threat_sensor(max_threat_signatures)
    integer :: threat_start_window(max_threat_signatures)
    integer :: threat_end_window(max_threat_signatures)
    integer :: threat_ramp_windows(max_threat_signatures)

    real(dp) :: threat_tx_mbps(max_threat_signatures)
    real(dp) :: threat_rx_mbps(max_threat_signatures)
    real(dp) :: threat_jitter_fraction(max_threat_signatures)

    character(len=max_len) :: baseline_file
    character(len=max_len) :: output_file
    character(len=max_len) :: pure_output_file
    character(len=max_len) :: config_file
    character(len=max_len) :: scenario_id
    character(len=max_len) :: scenario_label

    integer :: i
    integer :: s
    integer :: j
    integer :: ios
    integer :: seed_size
    integer :: active_count
    integer :: n_rows
    integer, allocatable :: seed(:)

    integer, allocatable :: baseline_window(:,:)
    integer, allocatable :: baseline_class(:,:)
    real(dp), allocatable :: baseline_time_seconds(:,:)
    real(dp), allocatable :: baseline_tx(:,:)
    real(dp), allocatable :: baseline_rx(:,:)
    real(dp), allocatable :: baseline_activity(:,:)
    real(dp), allocatable :: baseline_direction(:,:)

    real(dp) :: threat_tx
    real(dp) :: threat_rx
    real(dp) :: tx_scale
    real(dp) :: rx_scale
    real(dp) :: active_weight
    real(dp) :: activity
    real(dp) :: direction

    namelist /threat_signature_config/ &
        baseline_file, output_file, &
        n_sensors, n_windows, window_seconds, seed_base, &
        n_threat_signatures, &
        scenario_id, scenario_label

    baseline_file = 'baseline.csv'
    output_file = 'threat_signature.csv'

    n_sensors = 4
    n_windows = 2880
    window_seconds = 30
    seed_base = 24680

    n_threat_signatures = 0

    threat_number = 0
    threat_sensor = 0
    threat_start_window = 0
    threat_end_window = 0
    threat_ramp_windows = 0
    threat_tx_mbps = 0.0_dp
    threat_rx_mbps = 0.0_dp
    threat_jitter_fraction = 0.0_dp

    scenario_id = 'scenario_001'
    scenario_label = 'threat_scenario'

    config_file = 'threat_signature_config.nml'

    call get_command_argument(1, config_file)
    if (len_trim(config_file) == 0) config_file = 'threat_signature_config.nml'

    open(unit=20, file=trim(config_file), status='old', action='read', iostat=ios)
    if (ios == 0) then
        read(20, nml=threat_signature_config)
        close(20)
        print *, 'Read config file: ', trim(config_file)
    else
        print *, 'ERROR: could not open config file: ', trim(config_file)
        stop 1
    end if

    call read_threat_event_table(trim(config_file))
    call validate_config()

    allocate(baseline_window(n_windows, n_sensors))
    allocate(baseline_class(n_windows, n_sensors))
    allocate(baseline_time_seconds(n_windows, n_sensors))
    allocate(baseline_tx(n_windows, n_sensors))
    allocate(baseline_rx(n_windows, n_sensors))
    allocate(baseline_activity(n_windows, n_sensors))
    allocate(baseline_direction(n_windows, n_sensors))

    baseline_window = 0
    baseline_class = 0
    baseline_time_seconds = 0.0_dp
    baseline_tx = 0.0_dp
    baseline_rx = 0.0_dp
    baseline_activity = 0.0_dp
    baseline_direction = 0.0_dp

    call read_baseline(trim(baseline_file), n_rows)

    if (n_rows /= n_windows * n_sensors) then
        print *, 'WARNING: expected baseline rows = ', n_windows * n_sensors, ' but read rows = ', n_rows
    end if

    call random_seed(size=seed_size)
    allocate(seed(seed_size))

    do i = 1, seed_size
        seed(i) = seed_base + 104729 * i
    end do

    call random_seed(put=seed)

    pure_output_file = make_pure_filename(output_file)

    open(unit=10, file=trim(pure_output_file), status='replace', action='write', iostat=ios)
    if (ios /= 0) then
        print *, 'ERROR: could not open output file: ', trim(pure_output_file)
        stop 1
    end if

    write(10, '(A)') 'window,time_seconds,sensor,class,delta_tx,delta_rx,activity,direction'

    do i = 1, n_windows
        do s = 1, n_sensors
            threat_tx = 0.0_dp
            threat_rx = 0.0_dp
            active_count = 0

            do j = 1, n_threat_signatures
                if (threat_sensor(j) == s) then
                    if (baseline_window(i,s) >= threat_start_window(j) .and. &
                        baseline_window(i,s) <= threat_end_window(j)) then

                        active_count = active_count + 1

                        active_weight = window_weight(baseline_window(i,s), &
                            threat_start_window(j), threat_end_window(j), threat_ramp_windows(j))

                        tx_scale = 1.0_dp
                        rx_scale = 1.0_dp

                        if (threat_jitter_fraction(j) > 0.0_dp) then
                            tx_scale = max(0.0_dp, 1.0_dp + threat_jitter_fraction(j) * randn())
                            rx_scale = max(0.0_dp, 1.0_dp + threat_jitter_fraction(j) * randn())
                        end if

                        threat_tx = threat_tx + mbps_to_bytes_per_window( &
                            threat_tx_mbps(j), window_seconds) * active_weight * tx_scale

                        threat_rx = threat_rx + mbps_to_bytes_per_window( &
                            threat_rx_mbps(j), window_seconds) * active_weight * rx_scale
                    end if
                end if
            end do

            activity = threat_tx + threat_rx
            if (activity > 0.0_dp) then
                direction = (threat_tx - threat_rx) / activity
            else
                direction = 0.0_dp
            end if

            write(10, '(I0,",",F10.1,",",I0,",",I0,",",F18.3,",",F18.3,",",F18.3,",",F18.9)') &
                baseline_window(i,s), baseline_time_seconds(i,s), s, baseline_class(i,s), &
                threat_tx, threat_rx, activity, direction
        end do
    end do

    call write_embedded_metadata(10, trim(pure_output_file))

    close(10)

    call print_summary()

contains

    subroutine read_threat_event_table(path)
        implicit none
        character(len=*), intent(in) :: path

        character(len=line_len) :: line
        character(len=line_len) :: label
        character(len=line_len) :: values
        integer :: ios_local
        integer :: colon_pos
        logical :: have_threat
        logical :: have_sensor
        logical :: have_start
        logical :: have_end
        logical :: have_ramp
        logical :: have_tx
        logical :: have_rx
        logical :: have_jitter

        have_threat = .false.
        have_sensor = .false.
        have_start = .false.
        have_end = .false.
        have_ramp = .false.
        have_tx = .false.
        have_rx = .false.
        have_jitter = .false.

        open(unit=40, file=trim(path), status='old', action='read', iostat=ios_local)
        if (ios_local /= 0) then
            print *, 'ERROR: could not reopen config file while parsing threat table: ', trim(path)
            stop 1
        end if

        do
            read(40, '(A)', iostat=ios_local) line
            if (ios_local /= 0) exit

            line = adjustl(line)

            if (len_trim(line) == 0) cycle
            if (line(1:1) == '!') cycle
            if (line(1:1) == '&') cycle
            if (line(1:1) == '/') cycle

            colon_pos = index(line, ':')
            if (colon_pos <= 0) cycle

            label = lower_string(adjustl(line(1:colon_pos-1)))
            values = adjustl(line(colon_pos+1:))

            select case (trim(label))
            case ('threat')
                call parse_integer_row(values, threat_number, n_threat_signatures, 'Threat')
                have_threat = .true.
            case ('sensor')
                call parse_integer_row(values, threat_sensor, n_threat_signatures, 'Sensor')
                have_sensor = .true.
            case ('start window')
                call parse_integer_row(values, threat_start_window, n_threat_signatures, 'Start window')
                have_start = .true.
            case ('end window')
                call parse_integer_row(values, threat_end_window, n_threat_signatures, 'End window')
                have_end = .true.
            case ('ramp windows')
                call parse_integer_row(values, threat_ramp_windows, n_threat_signatures, 'Ramp windows')
                have_ramp = .true.
            case ('tx mbps')
                call parse_real_row(values, threat_tx_mbps, n_threat_signatures, 'TX Mbps')
                have_tx = .true.
            case ('rx mbps')
                call parse_real_row(values, threat_rx_mbps, n_threat_signatures, 'RX Mbps')
                have_rx = .true.
            case ('jitter fraction')
                call parse_real_row(values, threat_jitter_fraction, n_threat_signatures, 'Jitter fraction')
                have_jitter = .true.
            end select
        end do

        close(40)

        if (.not. have_threat) then
            print *, 'ERROR: threat-event table missing row: Threat:'
            stop 1
        end if

        if (.not. have_sensor) then
            print *, 'ERROR: threat-event table missing row: Sensor:'
            stop 1
        end if

        if (.not. have_start) then
            print *, 'ERROR: threat-event table missing row: Start window:'
            stop 1
        end if

        if (.not. have_end) then
            print *, 'ERROR: threat-event table missing row: End window:'
            stop 1
        end if

        if (.not. have_ramp) then
            print *, 'ERROR: threat-event table missing row: Ramp windows:'
            stop 1
        end if

        if (.not. have_tx) then
            print *, 'ERROR: threat-event table missing row: TX Mbps:'
            stop 1
        end if

        if (.not. have_rx) then
            print *, 'ERROR: threat-event table missing row: RX Mbps:'
            stop 1
        end if

        if (.not. have_jitter) then
            print *, 'ERROR: threat-event table missing row: Jitter fraction:'
            stop 1
        end if

        do i = 1, n_threat_signatures
            if (threat_number(i) /= i) then
                print *, 'ERROR: Threat row must enumerate threats from 1 through n_threat_signatures.'
                print *, 'Expected ', i, ' but found ', threat_number(i), ' at position ', i
                stop 1
            end if
        end do
    end subroutine read_threat_event_table


    subroutine parse_integer_row(values, output_values, expected_count, row_name)
        implicit none
        character(len=*), intent(in) :: values
        integer, intent(inout) :: output_values(:)
        integer, intent(in) :: expected_count
        character(len=*), intent(in) :: row_name

        character(len=line_len) :: buffer
        integer :: local_values(max_threat_signatures)
        integer :: count
        integer :: ios_local
        integer :: k

        buffer = trim(values)
        local_values = 0

        read(buffer, *, iostat=ios_local) (local_values(k), k = 1, max_threat_signatures)

        if (ios_local > 0) then
            print *, 'ERROR: could not parse integer row: ', trim(row_name)
            print *, trim(values)
            stop 1
        end if

        count = count_numeric_tokens(values)

        if (count /= expected_count) then
            print *, 'ERROR: row "', trim(row_name), '" has wrong number of entries.'
            print *, 'Expected ', expected_count, ' entries but found ', count
            print *, trim(values)
            stop 1
        end if

        do k = 1, expected_count
            output_values(k) = local_values(k)
        end do
    end subroutine parse_integer_row


    subroutine parse_real_row(values, output_values, expected_count, row_name)
        implicit none
        character(len=*), intent(in) :: values
        real(dp), intent(inout) :: output_values(:)
        integer, intent(in) :: expected_count
        character(len=*), intent(in) :: row_name

        character(len=line_len) :: buffer
        real(dp) :: local_values(max_threat_signatures)
        integer :: count
        integer :: ios_local
        integer :: k

        buffer = trim(values)
        local_values = 0.0_dp

        read(buffer, *, iostat=ios_local) (local_values(k), k = 1, max_threat_signatures)

        if (ios_local > 0) then
            print *, 'ERROR: could not parse real row: ', trim(row_name)
            print *, trim(values)
            stop 1
        end if

        count = count_numeric_tokens(values)

        if (count /= expected_count) then
            print *, 'ERROR: row "', trim(row_name), '" has wrong number of entries.'
            print *, 'Expected ', expected_count, ' entries but found ', count
            print *, trim(values)
            stop 1
        end if

        do k = 1, expected_count
            output_values(k) = local_values(k)
        end do
    end subroutine parse_real_row


    function count_numeric_tokens(values) result(count)
        implicit none
        character(len=*), intent(in) :: values
        integer :: count
        integer :: p
        integer :: n
        logical :: in_token
        character(len=1) :: ch

        count = 0
        in_token = .false.
        n = len_trim(values)

        do p = 1, n
            ch = values(p:p)

            if (ch == ' ' .or. ch == char(9) .or. ch == ',') then
                if (in_token) in_token = .false.
            else
                if (.not. in_token) then
                    count = count + 1
                    in_token = .true.
                end if
            end if
        end do
    end function count_numeric_tokens


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


    subroutine validate_config()
        implicit none
        integer :: k

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

        if (n_threat_signatures <= 0 .or. n_threat_signatures > max_threat_signatures) then
            print *, 'ERROR: invalid n_threat_signatures.'
            stop 1
        end if

        do k = 1, n_threat_signatures
            if (threat_sensor(k) < 1 .or. threat_sensor(k) > n_sensors) then
                print *, 'ERROR: invalid sensor for threat ', k
                stop 1
            end if

            if (threat_start_window(k) < 1 .or. threat_end_window(k) > n_windows .or. &
                threat_start_window(k) > threat_end_window(k)) then
                print *, 'ERROR: invalid time window for threat ', k
                stop 1
            end if

            if (threat_ramp_windows(k) < 0) then
                print *, 'ERROR: ramp windows must be nonnegative for threat ', k
                stop 1
            end if

            if (threat_tx_mbps(k) < 0.0_dp .or. threat_rx_mbps(k) < 0.0_dp) then
                print *, 'ERROR: threat magnitudes must be nonnegative for threat ', k
                stop 1
            end if

            if (threat_jitter_fraction(k) < 0.0_dp) then
                print *, 'ERROR: jitter fraction must be nonnegative for threat ', k
                stop 1
            end if
        end do
    end subroutine validate_config


    subroutine read_baseline(path, count_rows)
        implicit none
        character(len=*), intent(in) :: path
        integer, intent(out) :: count_rows

        character(len=line_len) :: line
        integer :: win
        integer :: sensor
        integer :: class_id
        integer :: ios_local
        real(dp) :: tsec
        real(dp) :: tx_value
        real(dp) :: rx_value
        real(dp) :: activity_value
        real(dp) :: direction_value

        count_rows = 0

        open(unit=30, file=trim(path), status='old', action='read', iostat=ios_local)
        if (ios_local /= 0) then
            print *, 'ERROR: could not open baseline file: ', trim(path)
            stop 1
        end if

        read(30, '(A)', iostat=ios_local) line

        do
            read(30, '(A)', iostat=ios_local) line
            if (ios_local /= 0) exit
            if (len_trim(line) == 0) cycle
            if (trim(line) == '__BASELINE_METADATA_JSON_BEGIN__') exit

            call parse_baseline_line(line, win, tsec, sensor, class_id, &
                tx_value, rx_value, activity_value, direction_value)

            if (win < 1 .or. win > n_windows .or. sensor < 1 .or. sensor > n_sensors) then
                print *, 'ERROR: invalid window or sensor in baseline file.'
                print *, trim(line)
                stop 1
            end if

            baseline_window(win, sensor) = win
            baseline_time_seconds(win, sensor) = tsec
            baseline_class(win, sensor) = class_id
            baseline_tx(win, sensor) = tx_value
            baseline_rx(win, sensor) = rx_value
            baseline_activity(win, sensor) = activity_value
            baseline_direction(win, sensor) = direction_value

            count_rows = count_rows + 1
        end do

        close(30)

        call validate_baseline_grid()
    end subroutine read_baseline


    subroutine validate_baseline_grid()
        implicit none
        integer :: win
        integer :: sensor

        do win = 1, n_windows
            do sensor = 1, n_sensors
                if (baseline_window(win, sensor) /= win) then
                    print *, 'ERROR: baseline.csv is missing window/sensor entry.'
                    print *, 'window = ', win, ' sensor = ', sensor
                    stop 1
                end if
            end do
        end do
    end subroutine validate_baseline_grid


    subroutine parse_baseline_line(line, win, tsec, sensor, class_id, tx_value, rx_value, activity_value, direction_value)
        implicit none
        character(len=*), intent(in) :: line
        integer, intent(out) :: win
        real(dp), intent(out) :: tsec
        integer, intent(out) :: sensor
        integer, intent(out) :: class_id
        real(dp), intent(out) :: tx_value
        real(dp), intent(out) :: rx_value
        real(dp), intent(out) :: activity_value
        real(dp), intent(out) :: direction_value

        character(len=line_len) :: fields(16)
        integer :: n_fields
        integer :: ios_local

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

        read(fields(4), *, iostat=ios_local) class_id
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


    function mbps_to_bytes_per_window(mbps, dt_seconds) result(bytes_window)
        implicit none
        real(dp), intent(in) :: mbps
        integer, intent(in) :: dt_seconds
        real(dp) :: bytes_window

        bytes_window = mbps * 1000000.0_dp * real(dt_seconds, dp) / 8.0_dp
    end function mbps_to_bytes_per_window


    function window_weight(window_idx, w_start, w_end, n_ramp) result(w)
        implicit none
        integer, intent(in) :: window_idx
        integer, intent(in) :: w_start
        integer, intent(in) :: w_end
        integer, intent(in) :: n_ramp
        real(dp) :: w
        integer :: distance_from_start
        integer :: distance_from_end
        integer :: edge_distance

        if (n_ramp <= 0) then
            w = 1.0_dp
            return
        end if

        distance_from_start = window_idx - w_start + 1
        distance_from_end = w_end - window_idx + 1
        edge_distance = min(distance_from_start, distance_from_end)

        if (edge_distance >= n_ramp) then
            w = 1.0_dp
        else
            w = real(edge_distance, dp) / real(n_ramp, dp)
        end if

        if (w < 0.0_dp) w = 0.0_dp
        if (w > 1.0_dp) w = 1.0_dp
    end function window_weight


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



    function make_pure_filename(input_name) result(output_name)
        implicit none
        character(len=*), intent(in) :: input_name
        character(len=max_len) :: output_name
        character(len=max_len) :: base
        integer :: n
        integer :: dot_pos

        base = trim(input_name)
        n = len_trim(base)
        output_name = ''

        if (n >= 9) then
            if (base(n-8:n) == '_pure.csv') then
                output_name = trim(base)
                return
            end if
        end if

        dot_pos = last_index(trim(base), '.csv')

        if (dot_pos > 0 .and. dot_pos + 3 == n) then
            output_name = trim(base(1:dot_pos-1)) // '_pure.csv'
        else
            output_name = trim(base) // '_pure.csv'
        end if
    end function make_pure_filename


    function last_index(text, pattern) result(pos)
        implicit none
        character(len=*), intent(in) :: text
        character(len=*), intent(in) :: pattern
        integer :: pos
        integer :: k
        integer :: n_text
        integer :: n_pattern

        pos = 0
        n_text = len_trim(text)
        n_pattern = len_trim(pattern)

        if (n_pattern <= 0 .or. n_text < n_pattern) return

        do k = 1, n_text - n_pattern + 1
            if (text(k:k+n_pattern-1) == pattern) pos = k
        end do
    end function last_index


    subroutine write_embedded_metadata(unit_id, data_file_name)
        implicit none
        integer, intent(in) :: unit_id
        character(len=*), intent(in) :: data_file_name
        integer :: k

        write(unit_id, '(A)') ''
        write(unit_id, '(A)') '__THREAT_SIGNATURE_METADATA_JSON_BEGIN__'
        write(unit_id, '(A)') '{'
        write(unit_id, '(A)') '  "generated_by": "threat_signature.f90",'
        write(unit_id, '(A)') '  "config_file": "' // trim(json_escape(config_file)) // '",'
        write(unit_id, '(A)') '  "baseline_file": "' // trim(json_escape(baseline_file)) // '",'
        write(unit_id, '(A)') '  "data_file": "' // trim(json_escape(data_file_name)) // '",'
        write(unit_id, '(A)') '  "data_content": "pure_threat_signature",'
        write(unit_id, '(A)') '  "scenario_id": "' // trim(json_escape(scenario_id)) // '",'
        write(unit_id, '(A)') '  "scenario_label": "' // trim(json_escape(scenario_label)) // '",'
        write(unit_id, '(A,I0,A)') '  "n_sensors": ', n_sensors, ','
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
        write(unit_id, '(A)') '    {"name": "delta_tx", "unit": "bytes_per_window", "source": "threat_tx"},'
        write(unit_id, '(A)') '    {"name": "delta_rx", "unit": "bytes_per_window", "source": "threat_rx"},'
        write(unit_id, '(A)') '    {"name": "activity", "unit": "bytes_per_window", "definition": "delta_tx + delta_rx"},'
        write(unit_id, '(A)') '    {"name": "direction", "unit": "unitless", "definition": "(delta_tx - delta_rx) / activity"}'
        write(unit_id, '(A)') '  ],'
        write(unit_id, '(A,I0,A)') '  "n_threat_signatures": ', n_threat_signatures, ','
        write(unit_id, '(A)') '  "threat_signature_parameters": ['

        do k = 1, n_threat_signatures
            write(unit_id, '(A,I0,A,I0,A,I0,A,I0,A,I0,A,F12.6,A,F12.6,A,F12.6,A)', advance='no') &
                '    {"threat": ', threat_number(k), &
                ', "sensor": ', threat_sensor(k), &
                ', "start_window": ', threat_start_window(k), &
                ', "end_window": ', threat_end_window(k), &
                ', "ramp_windows": ', threat_ramp_windows(k), &
                ', "tx_mbps": ', threat_tx_mbps(k), &
                ', "rx_mbps": ', threat_rx_mbps(k), &
                ', "jitter_fraction": ', threat_jitter_fraction(k), '}'
            if (k < n_threat_signatures) then
                write(unit_id, '(A)') ','
            else
                write(unit_id, '(A)') ''
            end if
        end do

        write(unit_id, '(A)') '  ]'
        write(unit_id, '(A)') '}'
        write(unit_id, '(A)') '__THREAT_SIGNATURE_METADATA_JSON_END__'
    end subroutine write_embedded_metadata


    function json_escape(input) result(output)
        implicit none
        character(len=*), intent(in) :: input
        character(len=max_len) :: output
        integer :: idx
        integer :: out_idx
        character(len=1) :: ch

        output = ''
        out_idx = 1

        do idx = 1, len_trim(input)
            ch = input(idx:idx)
            if (ch == '"') then
                if (out_idx <= max_len - 1) then
                    output(out_idx:out_idx) = '\\'
                    output(out_idx+1:out_idx+1) = '"'
                    out_idx = out_idx + 2
                end if
            else if (ch == '\\') then
                if (out_idx <= max_len - 1) then
                    output(out_idx:out_idx) = '\\'
                    output(out_idx+1:out_idx+1) = '\\'
                    out_idx = out_idx + 2
                end if
            else
                if (out_idx <= max_len) then
                    output(out_idx:out_idx) = ch
                    out_idx = out_idx + 1
                end if
            end if
        end do
    end function json_escape


    subroutine print_summary()
        implicit none
        integer :: k

        print *, 'Wrote pure threat signature file: ', trim(pure_output_file)
        print *, 'Baseline input file       : ', trim(baseline_file)
        print *, 'Threat signatures         : ', n_threat_signatures
        print *, ''
        print *, 'Parsed threat-event table:'
        print *, 'Threat  Sensor  Start  End    Ramp   TX Mbps   RX Mbps   Jitter'
        print *, '------  ------  -----  -----  -----  -------   -------   ------'

        do k = 1, n_threat_signatures
            print '(I6,2X,I6,2X,I5,2X,I5,2X,I5,2X,F7.3,3X,F7.3,3X,F6.3)', &
                threat_number(k), threat_sensor(k), threat_start_window(k), &
                threat_end_window(k), threat_ramp_windows(k), threat_tx_mbps(k), &
                threat_rx_mbps(k), threat_jitter_fraction(k)
        end do
    end subroutine print_summary

end program threat_signature
