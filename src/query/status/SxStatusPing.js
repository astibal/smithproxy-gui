import React from 'react';
import $ from "jquery";

export default class SxStatusPing extends React.Component {

    constructor(props) {
        super(props);
        this.state = {
            status: "",
            version: ""
        }
    }

    componentWillUnmount() {
        clearInterval(this.interval);
    }

    componentDidMount() {
        this.interval = setInterval(() => this.fetch(), 2000);
        this.fetch();
    }

    fetch() {
        var context = this;

        $.ajax({
            url: 'http://localhost:55555/api/status/ping',
            method: 'GET',
            success: function(response) {

                context.setState({
                    status: response.status,
                    version: response.version,
                    uptime: response.uptime_str
                });
            }
        });
    }

    render() {
        return (
            <div>
                <p><strong>Smithproxy status:</strong> {this.state.status}</p>
                <p><strong>Version:</strong> {this.state.version}</p>
                <p><strong>Uptime:</strong> {this.state.uptime}</p>
            </div>
        );
    }
}
