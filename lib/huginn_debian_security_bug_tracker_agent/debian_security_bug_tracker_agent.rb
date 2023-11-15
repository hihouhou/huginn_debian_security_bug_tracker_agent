module Agents
  class DebianSecurityBugTrackerAgent < Agent
    include FormConfigurable
    can_dry_run!
    no_bulk_receive!
    default_schedule 'every_2h'

    description do
      <<-MD
      The Debian Security Bug Tracker Agent checks updates from and creates an event when new CVE or CVE update.

      `buster` to check only for Buster version.

      `bullseye` to check only for Bullseye version.

      `bookworm` to check only for Bookworm version.

      `trixie` to check only for Trixie version.

      `sid` to check only for Sid version.

      `only_this_year` to limit event / checks because there is a lot of CVE...

      `debug` to add verbosity.

      `expected_receive_period_in_days` is used to determine if the Agent is working. Set it to the maximum number of days
      that you anticipate passing without this Agent receiving an incoming Event.
      MD
    end

    event_description <<-MD
      Events look like this:

          {
            "status": "open",
            "repositories": {
              "buster": "1:1.2.11.dfsg-1+deb10u1",
              "buster-security": "1:1.2.11.dfsg-1+deb10u2"
            },
            "urgency": null,
            "nodsa": null,
            "nodsa_reason": null,
            "cve": "CVE-2023-45853",
            "os": "buster",
            "package": "zlib",
            "description": "MiniZip in zlib through 1.3 has an integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_64 via a long filename, comment, or extra field. NOTE: MiniZip is not a supported part of the zlib product.",
            "scope": "local",
            "debianbug": null
          }
    MD

    def default_options
      {
        'buster' => 'true',
        'bullseye' => 'true',
        'bookworm' => 'true',
        'trixie' => 'true',
        'sid' => 'true',
        'debug' => 'false',
        'only_this_year' => 'true',
        'expected_receive_period_in_days' => '2'
      }
    end

    form_configurable :buster, type: :boolean
    form_configurable :bullseye, type: :boolean
    form_configurable :bookworm, type: :boolean
    form_configurable :trixie, type: :boolean
    form_configurable :sid, type: :boolean
    form_configurable :expected_receive_period_in_days, type: :string
    form_configurable :debug, type: :boolean
    form_configurable :only_this_year, type: :boolean
    def validate_options

      if options.has_key?('buster') && boolify(options['buster']).nil?
        errors.add(:base, "if provided, buster must be true or false")
      end

      if options.has_key?('bullseye') && boolify(options['bullseye']).nil?
        errors.add(:base, "if provided, bullseye must be true or false")
      end

      if options.has_key?('bookworm') && boolify(options['bookworm']).nil?
        errors.add(:base, "if provided, bookworm must be true or false")
      end

      if options.has_key?('trixie') && boolify(options['trixie']).nil?
        errors.add(:base, "if provided, trixie must be true or false")
      end

      if options.has_key?('sid') && boolify(options['sid']).nil?
        errors.add(:base, "if provided, sid must be true or false")
      end

      if options.has_key?('debug') && boolify(options['debug']).nil?
        errors.add(:base, "if provided, debug must be true or false")
      end

      if options.has_key?('only_this_year') && boolify(options['only_this_year']).nil?
        errors.add(:base, "if provided, only_this_year must be true or false")
      end

      unless options['expected_receive_period_in_days'].present? && options['expected_receive_period_in_days'].to_i > 0
        errors.add(:base, "Please provide 'expected_receive_period_in_days' to indicate how many days can pass before this Agent is considered to be not working")
      end
    end

    def working?
      event_created_within?(options['expected_receive_period_in_days']) && !recent_error_logs?
    end

    def check
      fetch
    end

    private

    def log_curl_output(code,body)

      log "request status : #{code}"

      if interpolated['debug'] == 'true'
        log "body"
        log body
      end

    end

    def fetch
      uri = URI.parse("https://security-tracker.debian.org/tracker/data/json")
      response = Net::HTTP.get_response(uri)
      
      log_curl_output(response.code, response.body)
      
      parsed_data = JSON.parse(response.body)
      packages_data = {}
      current_year = Time.now.year
      
      parsed_data.each do |package_name, cve_data|
        cve_array = []
      
        cve_data&.each do |cve, cve_details|
          cve_versions = {}
      
          cve_details["releases"]&.each do |version, release_data|
            if version.downcase.include?('buster') && interpolated['buster'] == "true"
              cve_versions[version] = { "status" => release_data["status"] }
            end
            if version.downcase.include?('bullseye') && interpolated['bullseye'] == "true"
              cve_versions[version] = { "status" => release_data["status"] }
            end
            if version.downcase.include?('bookworm') && interpolated['bookworm'] == "true"
              cve_versions[version] = { "status" => release_data["status"] }
            end
            if version.downcase.include?('trixie') && interpolated['trixie'] == "true"
              cve_versions[version] = { "status" => release_data["status"] }
            end
            if version.downcase.include?('sid') && interpolated['sid'] == "true"
              cve_versions[version] = { "status" => release_data["status"] }
            end
          end
      
          cve_entry = {
            cve => cve_versions
          }
      
          if interpolated['only_this_year'] == "true"
            if cve =~ /CVE-(\d{4})-\d+/
              extracted_year = $1.to_i
              if extracted_year == current_year
                cve_array << cve_entry
              end
            end
          else
            cve_array << cve_entry
          end
        end
      
        if cve_array.any?
          packages_data[package_name] = cve_array
        end
      end

#      uri = URI.parse("https://security-tracker.debian.org/tracker/data/json")
#      response = Net::HTTP.get_response(uri)
#
#      log_curl_output(response.code,response.body)
#      
#      parsed_data = JSON.parse(response.body)
#      packages_data = {}
#      if interpolated['only_this_year'] == "true"
#        current_year = Time.now.year
#        parsed_data.each do |package_name, cve_data|
#          cves_for_year = Set.new
#          cve_data.each do |cve, content|
#            if cve =~ /CVE-(\d{4})-\d+/
#              extracted_year = $1.to_i
#              if extracted_year == current_year
#                cves_for_year.add(cve)
#              end
#            end
#          end
#          if cves_for_year.any?
#            packages_data[package_name] = cves_for_year.to_a
#          end
#        end
#      else
##        parsed_data.each do |package_name, cve_data|
##          packages_data[package_name] = cve_data.keys
##        end
#        parsed_data.each do |package_name, cve_data|
#          cve_array = []
#        
#          cve_data&.each do |cve, cve_details|
#            cve_versions = {}
#        
#            cve_details["releases"]&.each do |version, release_data|
#              if version.downcase.include?('buster') && interpolated['buster'] == "true"
#                cve_versions[version] = { "status" => release_data["status"] }
#              end
#              if version.downcase.include?('bullseye') && interpolated['bullseye'] == "true"
#                cve_versions[version] = { "status" => release_data["status"] }
#              end
#              if version.downcase.include?('bookworm') && interpolated['bookworm'] == "true"
#                cve_versions[version] = { "status" => release_data["status"] }
#              end
#              if version.downcase.include?('trixie') && interpolated['trixie'] == "true"
#                cve_versions[version] = { "status" => release_data["status"] }
#              end
#              if version.downcase.include?('sid') && interpolated['sid'] == "true"
#                cve_versions[version] = { "status" => release_data["status"] }
#              end
#            end
#        
#            cve_entry = {
#              cve => cve_versions
#            }
#        
#            cve_array << cve_entry
#          end
#        
#          packages_data[package_name] = cve_array
#        end
#
#      end

      if packages_data != memory['last_status']
        if "#{memory['last_status']}" == ''
          parsed_data.each do |package, cve_data|
#            log package
            cve_data.each do |cve, content|
              if interpolated['only_this_year'] == "true"
                if cve =~ /CVE-(\d{4})-\d+/
                  extracted_year = $1.to_i
                  if extracted_year == current_year
                    content['releases'].each do |release|
#                      log release
                      if interpolated['buster'] == "true" && release.first == "buster"
                        can_i_create = true
                      end
                      if interpolated['bullseye'] == "true" && release.first == "bullseye"
                        can_i_create = true
                      end
                      if interpolated['bookworm'] == "true" && release.first == "bookworm"
                        can_i_create = true
                      end
                      if interpolated['trixie'] == "true" && release.first == "trixie"
                        can_i_create = true
                      end
                      if interpolated['sid'] == "true" && release.first == "sid"
                        can_i_create = true
                      end
#                        log release.first
#                        log release
                      if can_i_create == true
                        generated_event = release[1]
                        generated_event['urgency'] = release[2]
                        generated_event['nodsa'] = release[3]
                        generated_event['nodsa_reason'] = release[4]
                        generated_event['cve'] = cve
                        generated_event['os'] = release.first
                        generated_event['package'] = package
                        generated_event['description'] = content['description']
                        generated_event['scope'] = content['scope']
                        generated_event['debianbug'] = content['debianbug']
                        create_event payload: generated_event
                      end
                    end
                  end
                end
              else
                log cve
              end
            end
          end
        else
          parsed_data.each do |package, cve_data|
            found = false
            cve_data.each do |cve, content|
              if interpolated['only_this_year'] == "true"
                if cve =~ /CVE-(\d{4})-\d+/
                  extracted_year = $1.to_i  # $1 contient la première capture de la regex
                  if extracted_year == current_year
                    content['releases'].each do |release|
                      if interpolated['buster'] == "true" && release.first == "buster"
                        can_i_create = true
                      end
                      if interpolated['bullseye'] == "true" && release.first == "bullseye"
                        can_i_create = true
                      end
                      if interpolated['bookworm'] == "true" && release.first == "bookworm"
                        can_i_create = true
                      end
                      if interpolated['trixie'] == "true" && release.first == "trixie"
                        can_i_create = true
                      end
                      if interpolated['sid'] == "true" && release.first == "sid"
                        can_i_create = true
                      end
                      memory['last_status'].each do |packagebis, cve_databis|
                        if package == packagebis
                          cve_databis.each do |per_os_status|
                            if per_os_status.keys[0] == cve
#                              log "#{package} //// #{per_os_status.values[0].keys[0]} #{release.first} //// #{per_os_status.values[0].values[0].values[0]} #{release[1].values[0]}"
                              if !per_os_status.values[0].keys[0].nil? && per_os_status.values[0].keys[0] == release.first && !release[1].values[0].nil? && per_os_status.values[0].values[0].values[0] == release[1].values[0]
                                found = true
                              end
                            end
                          end
                        end
                      end
                      if can_i_create == true && found == false
                        generated_event = release[1]
                        generated_event['urgency'] = release[2]
                        generated_event['nodsa'] = release[3]
                        generated_event['nodsa_reason'] = release[4]
                        generated_event['cve'] = cve
                        generated_event['os'] = release.first
                        generated_event['package'] = package
                        generated_event['description'] = content['description']
                        generated_event['scope'] = content['scope']
                        generated_event['debianbug'] = content['debianbug']
                        create_event payload: generated_event
                      end
                    end
                  end
                end
              else
                log cve
              end
            end
          end
        end
      end
      memory['last_status'] = packages_data
    end
  end
end
