import React from 'react';
import $ from "jquery";

export default class SxProxyList extends React.Component {

    constructor(props) {
        super(props);
        this.refreshIntervalSeconds = 1;
        this.state = {
            status: "",
            version: ""
        }
    }

    componentWillUnmount() {
        clearInterval(this.interval);
    }

    componentDidMount() {
        this.interval = setInterval(() => this.fetch(), this.refreshIntervalSeconds*1000);
        this.fetch();
    }

    fetch() {
        const context = this;

        $.ajax({
            url: 'http://localhost:55555/api/diag/proxy/session/list?verbosity=7&active=0&tlsinfo=1&oid=0',
            dataType: 'json',
            method: 'GET',
            success: function(response) {

                context.setState({ data: response });
            }
        });
    }

    render() {
        if (this.state.data) {
            return (
                <div>
                    <table>
                        <tbody>{this.state.data.map(function (item, key) {
                            return (
                                <tr key = {key}>
                                    <td>{item.oid}</td>
                                    <td>{item.left[0].com}</td>
                                    <td>{item.left[0].host}</td>
                                    <td>{item.left[0].port}</td>
                                    <td>{item.right[0].host}</td>
                                    <td>{item.right[0].port}</td>
                                    <td>{item.stats.speed.down_str}</td>
                                    <td>{item.stats.speed.up_str}</td>
                                </tr>
                            )

                        })}</tbody>
                    </table>
                </div>
            );
        } else {
            return ( "No data" );
        }
    }
}
